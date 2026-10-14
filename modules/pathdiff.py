"""
# pathdiff.py
Compare two path lookups. Notebook-facing — this is the only module that pulls
in pandas, which is why it is kept out of `pathgraph.py` (the CLI imports that
one and never needs a DataFrame).

Two ways to diff, both returning a hop-aligned table:

- `diff_paths()`      — run TWO lookups, align them locally with difflib.
- `overlay_diff()`    — ask IP Fabric to overlay one snapshot on another in a
                        SINGLE graph call; the merged graph comes back with
                        every node/edge already tagged by change status.
"""

import difflib
from collections import defaultdict

import pandas as pd

from .pathgraph import (
    SOURCE,
    _graph,
    enrich,
    flatten,
    hop_details,
    hop_state,
    node_id,
    ordered_ids,
)


def hop_label(h):
    io = f"{','.join(h['ingress'] or ['·'])} → {','.join(h['egress'] or ['·'])}"
    return f"{h['device']} ({h['type']})  [{io}]"


def hop_changed(ha, hb):
    """For the SAME device on both sides: did its forwarding behaviour change?
    True if the egress interface(s) or the security/drop verdict differ."""
    return (hop_state(ha) != hop_state(hb)) or (
        (ha["egress"] or []) != (hb["egress"] or [])
    )


def diff_paths(res_a, res_b, name_a="Day 1", name_b="Day 2"):
    """Return a hop-aligned diff DataFrame comparing two path-lookup results.
    Alignment is by device name (difflib); common devices line up on one row,
    divergence shows up as removed (name_a only) / added (name_b only) rows."""
    a, b = flatten(enrich(res_a)), flatten(enrich(res_b))
    sm = difflib.SequenceMatcher(
        a=[h["device"] for h in a], b=[h["device"] for h in b]
    )

    def row(mark, ha, hb):
        return {
            "": mark,
            name_a: hop_label(ha) if ha else "",
            f"{name_a} state": hop_state(ha) if ha else "",
            name_b: hop_label(hb) if hb else "",
            f"{name_b} state": hop_state(hb) if hb else "",
        }

    rows = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        seg_a, seg_b = a[i1:i2], b[j1:j2]
        if tag == "equal":  # SAME device on both sides
            for ha, hb in zip(seg_a, seg_b):
                rows.append(row("≠" if hop_changed(ha, hb) else "=", ha, hb))
        else:  # replace/delete/insert = divergence
            for ha in seg_a:  # devices only in path A
                rows.append(row("−", ha, None))
            for hb in seg_b:  # devices only in path B
                rows.append(row("+", None, hb))
    return pd.DataFrame(rows)


def style_diff(df):
    """Colour the divergence for display in Jupyter."""
    colors = {
        "=": "",
        "≠": "background-color:#fff3cd",  # amber: same node, changed forwarding
        "−": "background-color:#f8d7da",  # red:   only in path A
        "+": "background-color:#d1e7dd",  # green: only in path B
    }
    return (
        df.style.apply(lambda r: [colors.get(r[""], "")] * len(r), axis=1).hide(
            axis="index"
        )
    )


# ── Server-side diff via IP Fabric's compare overlay ──────────────────────────
# diff_paths() above runs TWO path lookups and aligns them locally with difflib.
# The alternative below asks IP Fabric to overlay one snapshot on another in a
# SINGLE graph call — the merged graph comes back with every node/edge already
# tagged by change status via its style colour, so no local alignment is needed.
#
#   diag = Diagram(ipf=ipf_base)                       # client pinned to BASE snap
#   res  = compare_snapshots(diag, uni, COMPARE_SNAP)  # or diag.model(..., overlay=...)
#   display(style_overlay_diff(overlay_diff(res)))     # colour-coded table
#   show_overlay(overlay_hops(res))                    # colour-coded tree
#
# Colour semantics (node = style.background, edge = style.line.color):
#   gray  / #A0A0A0  unchanged  — hop is in both paths
#   red   / #FF6666  removed    — hop only in the BASE snapshot's path
#   green / #6FB96F  added      — hop only in the COMPARE snapshot's path
#
# IMPORTANT: pathlookup.decisions (VRF / security verdict / drop reason) are only
# present for BASE-snapshot hops (unchanged + removed). "Added" (green) hops carry
# interfaces but NO forwarding verdict — so point the base client at whichever
# snapshot you most need the verdicts for (usually the broken/post-change one).

_NODE_STATUS = {
    "gray": "unchanged",
    "grey": "unchanged",
    "green": "added",
    "red": "removed",
}


def compare_snapshots(diag, params, snapshot_to_compare, **kwargs):
    """Run a path lookup as a compare overlay and return the merged result.

    BASE snapshot = the snapshot the diag's IPFClient is pinned to.
    COMPARE snapshot = snapshot_to_compare.
    The returned PathLookupResult's node/edge styles encode added/removed/unchanged.

    Note: do NOT pass snapshot_id — with a compare overlay the SDK derives the
    base from the client and raises if snapshot_id is also given."""
    return diag.model(
        params, overlay={"snapshotToCompare": snapshot_to_compare}, **kwargs
    )


def node_status(node):
    """'added' / 'removed' / 'unchanged' / None from an overlay node's style."""
    bg = (node.style.background if node.style else None) or ""
    return _NODE_STATUS.get(bg.lower())


# Edge line colours carry the same semantics as node backgrounds (decimal RGB).
_EDGE_STATUS = {0xA0A0A0: "unchanged", 0x6FB96F: "added", 0xFF6666: "removed"}


def edge_status(edge):
    """'added' / 'removed' / 'unchanged' / None from an overlay edge's line colour."""
    color = edge.style.line.color if (edge.style and edge.style.line) else None
    return _EDGE_STATUS.get(color)


def _side_interfaces(res, keep):
    """Per-node (ingress, egress) interface sets built from ONLY the edges whose
    status is in `keep`. Lets us split a node's interfaces by snapshot side:
      base    (Day 1) = edges that are {'unchanged', 'removed'}
      compare (Day 2) = edges that are {'unchanged', 'added'}
    An interface that changed on an 'unchanged' node shows up as different values
    on each side (the old edge is 'removed', the new one 'added')."""
    ingress, egress = defaultdict(set), defaultdict(set)
    for e in res.edges.values():
        if edge_status(e) not in keep:
            continue
        if not e.prevEdgeIds and not e.nextEdgeIds:
            continue
        if e.targetIfaceName:
            ingress[node_id(e.target)].add(e.targetIfaceName)
        if e.sourceIfaceName:
            egress[node_id(e.source)].add(e.sourceIfaceName)
    return ingress, egress


def _fmt_io(ingress, egress):
    """'in → out' for a set of ingress/egress interfaces, '' if the node has none
    on this side (e.g. an added node has no base-side interfaces)."""
    if not ingress and not egress:
        return ""
    return f"{','.join(sorted(ingress)) or '·'} → {','.join(sorted(egress)) or '·'}"


def overlay_hops(res):
    """enrich() output for a compare-overlay result: same nested hop structure,
    but each hop dict also carries 'id' (the DEVICE id, for divergence_point()/
    overlay_diff()) and 'status' (added/removed/unchanged)."""
    edges, _, preds = _graph(res)
    d = hop_details(res)
    start_edges = [eid for eid in edges if not preds[eid]]
    if SOURCE in d and start_edges:
        start_node = edges[start_edges[0]][0]
        d[SOURCE]["id"] = start_node
        d[SOURCE]["status"] = node_status(res.nodes[start_node])
    for eid, (_, target_id) in edges.items():
        if eid in d:
            d[eid]["id"] = target_id
            d[eid]["status"] = node_status(res.nodes[target_id])

    def render(x):
        return [render(i) for i in x] if isinstance(x, list) else d[x]

    return render(ordered_ids(res))


_STATUS_MARK = {"unchanged": "=", "removed": "−", "added": "+"}


def overlay_diff(res, name_a="base", name_b="compare"):
    """Server-side path diff -> one-row-per-hop DataFrame, built entirely from
    IP Fabric's compare overlay in `res` (one API call, no difflib).

    Interfaces are split per side ({name_a} iface / {name_b} iface) from the edge
    colours, so each snapshot's ingress→egress is shown independently. The verdict
    column is base-side only — decisions don't exist for added (compare-only) hops."""
    base_in, base_eg = _side_interfaces(res, {"unchanged", "removed"})  # name_a side
    comp_in, comp_eg = _side_interfaces(res, {"unchanged", "added"})  # name_b side
    seen, rows = set(), []
    for h in flatten(overlay_hops(res)):
        nid = h["id"]
        if nid in seen:  # ordered_ids can revisit a join node
            continue
        seen.add(nid)
        st = h.get("status")
        # decisions only exist for base-side hops (unchanged/removed)
        verdict = (
            hop_state(h) if st in ("unchanged", "removed") else f"({name_b}-only)"
        )
        rows.append(
            {
                "": _STATUS_MARK.get(st, "?"),
                "device": h["device"],
                "type": h["type"],
                f"{name_a} iface": _fmt_io(
                    base_in.get(nid, set()), base_eg.get(nid, set())
                ),
                f"{name_b} iface": _fmt_io(
                    comp_in.get(nid, set()), comp_eg.get(nid, set())
                ),
                "status": st or "?",
                f"{name_a} verdict": verdict,
            }
        )
    return pd.DataFrame(rows)


def divergence_point(res):
    """Device whose forwarding first changed between the two snapshots — the
    earliest hop (in path order) that has an added OR removed outgoing edge.
    This is where the two paths start to diverge, and the device whose routing /
    interface state you want to diff to explain *why*. Returns the hostname
    (str), or None if the paths never diverge.

    Read straight from the compare overlay, so it needs no routing-table
    heuristic: an added/removed outgoing edge means this device sent the traffic
    somewhere different in one snapshot than the other."""
    changed_out = {
        node_id(e.source)
        for e in res.edges.values()
        if edge_status(e) in ("added", "removed")
    }
    for h in flatten(overlay_hops(res)):  # path order (trunk before branches)
        if h["id"] in changed_out:
            return h["device"]
    return None


# Real network devices (exclude host / cloud / transit pseudo-nodes).
_PATH_DEVICE_TYPES = {"router", "switch", "l3switch", "fw", "lb"}


def path_devices(res, types=_PATH_DEVICE_TYPES):
    """Sorted hostnames of the network devices in a path-lookup result. Reads them
    straight off the result's nodes — no separate inventory call. Works on a
    single-snapshot result, or on a compare overlay (which merges both paths, so
    you get every device that appears in either path in one shot)."""
    return sorted({n.label for n in res.nodes.values() if n.type in types})


def overlay_path_devices(res, types=_PATH_DEVICE_TYPES):
    """From a compare overlay, split the devices by which path they belong to,
    using each node's change status. Returns sorted hostname lists:
        common       – in both paths (unchanged)
        base_only    – only in the base path (removed)
        compare_only – only in the compare path (added)
        base         – common + base_only   (the whole base path)
        compare      – common + compare_only (the whole compare path)"""
    common, base_only, compare_only = set(), set(), set()
    for n in res.nodes.values():
        if n.type not in types:
            continue
        st = node_status(n)
        (
            base_only
            if st == "removed"
            else compare_only
            if st == "added"
            else common
        ).add(n.label)
    return {
        "common": sorted(common),
        "base_only": sorted(base_only),
        "compare_only": sorted(compare_only),
        "base": sorted(common | base_only),
        "compare": sorted(common | compare_only),
    }


def style_overlay_diff(df):
    """Colour an overlay_diff() table for display in Jupyter."""
    colors = {
        "=": "",  # unchanged: plain
        "−": "background-color:#f8d7da",  # red:   removed (base only)
        "+": "background-color:#d1e7dd",  # green: added   (compare only)
    }
    return (
        df.style.apply(lambda r: [colors.get(r[""], "")] * len(r), axis=1).hide(
            axis="index"
        )
    )


_STATUS_GLYPH = {"added": "⊕", "removed": "⊖", "unchanged": "•"}
_STATUS_ANSI = {"added": "\033[32m", "removed": "\033[31m", "unchanged": ""}
_ANSI_RESET = "\033[0m"


def _branch_label(branch):
    """Summarise a parallel branch by the change status(es) it contains, so each
    branch of a divergence is clearly the removed (base) or added (compare) leg."""
    sts = set()

    def collect(seq):
        for it in seq:
            collect(it) if isinstance(it, list) else sts.add(it.get("status"))

    collect(branch)
    sts.discard(None)
    non_common = sts - {"unchanged"}
    if non_common == {"removed"}:
        return "removed — base only"
    if non_common == {"added"}:
        return "added — compare only"
    if not non_common:
        return "unchanged (redundant link)"
    return "mixed"


def show_overlay(structure, indent=0, color=True):
    """Like pathgraph.show(), but for a compare-overlay result: each hop is tagged
    added(⊕, green) / removed(⊖, red) / unchanged(•), and security/drop detail
    is only printed for base-side hops (where decisions exist). Where the paths
    diverge, each leg is printed under its own labelled branch header."""
    for hop in structure:
        if isinstance(hop, list):
            print("  " * indent + "╠═ diverges:")
            for br in hop:
                print("  " * (indent + 1) + f"├─ {_branch_label(br)}:")
                show_overlay(br, indent + 2, color)
            continue
        st = hop.get("status")
        glyph = _STATUS_GLYPH.get(st, "•")
        tag = f"  [{st}]" if st else ""
        io = f" [{','.join(hop['ingress'] or ['-'])} → {','.join(hop['egress'] or ['-'])}]"
        flag = "  ⛔ BLOCKED" if hop["blocked"] else ""
        line = f"{glyph} {hop['device']:11s} ({hop['type']}){io}{tag}{flag}"
        if color and _STATUS_ANSI.get(st):
            line = f"{_STATUS_ANSI[st]}{line}{_ANSI_RESET}"
        print("  " * indent + line)
        if st in (None, "unchanged", "removed"):  # verdicts are base-side only
            for s in hop["security"] or []:
                print(
                    "  " * indent
                    + f"     🔒 {s['type']} '{s['policy']}' rule={s['rule']} → {s['result']}"
                )
            if hop["dropped"]:
                print("  " * indent + f"     ✗ {hop['drop_reason']}")
