"""
# pathgraph.py
Walk an IP Fabric PathLookup graph and enrich every hop with the forwarding
decision that applied to it.

Works on the SDK's typed result (`Diagram.model(...)` -> `PathLookupResult`), not
on the raw JSON, so no edge-id string parsing is needed anywhere.

The two things this gets right that a naive `nextEdgeIds[0]` walk does not:

- ECMP / redundant legs are kept as parallel branches instead of being truncated.
- A device traversed twice (load-balancer hairpin) gets one entry per *visit*,
  each with only the decision that applied to that pass.

No pandas here on purpose — the CLI imports this module. Snapshot-compare and
DataFrame diffs live in `pathdiff.py`.
"""

from collections import defaultdict, deque

from rich import print
from rich.markup import escape

from .utilis import display_severity

EVENT_HEADER_TYPE = ("vxlan", "capwap", "gre", "esp", "mpls", "ip", "fp")
L2_EXCLUSION_PROTOCOL = ("l2", "fp")
CHAIN_SWITCHING = "switching-nexthop"
SEVERITY_RED = 30  # SeverityInfo.severity for a deny/drop

SOURCE = "__source__"  # sentinel hop-id for the originating host (no incoming edge)
_START = object()  # sentinel: "at the source host, no edge taken yet"


# ---------- graph ordering (returns nested edge-IDs) ----------
def node_id(endpoint):
    """Node id of an edge endpoint, whichever shape it is in.

    Straight off the wire (`PathLookupResult(**json)`, i.e. the --file replay)
    `edge.source` / `edge.target` are node-id strings. `Diagram.model()` then
    walks the result and swaps in the Node object itself. Both shapes reach this
    module, so never touch `.source` / `.target` without going through here."""
    return endpoint if isinstance(endpoint, str) else endpoint.id


def _graph(res):
    """Adjacency keyed by EDGE id (unique, from res.edges), not device id.

    A device can legitimately appear more than once in a single path — e.g. a
    one-arm load balancer: client -> LB, the LB terminates the connection and
    originates a NEW flow that re-enters the same core switches on its way to
    a backend on another subnet. Modelling adjacency on device id conflates
    those two distinct traversals into what looks like a graph cycle, which
    sends a node-keyed walk into infinite recursion — and, once that is patched
    by dropping the "cycle", incorrectly truncates the path right at the load
    balancer instead of continuing on to the real backend host.
    Since res.edges is a finite dict and nextEdgeIds only ever references keys
    within it, building the graph on edge id is a DAG by construction: no
    cycle is possible, so no cycle-breaking is needed."""
    edges = {
        eid: (node_id(e.source), node_id(e.target))
        for eid, e in res.edges.items()
        if e.prevEdgeIds or e.nextEdgeIds
    }
    if not edges:
        # Single-edge path (source and destination on the same device): the one
        # edge has neither a previous nor a next, so the filter above empties it.
        edges = {
            eid: (node_id(e.source), node_id(e.target)) for eid, e in res.edges.items()
        }
    succ, preds = defaultdict(list), defaultdict(list)
    for eid in edges:
        for nx in res.edges[eid].nextEdgeIds or []:
            if nx in edges:
                succ[eid].append(nx)
                preds[nx].append(eid)
    return edges, succ, preds


def _walked_ids(seq):
    """Every edge id inside a (possibly nested) walk result."""
    out = set()
    for item in seq:
        out |= _walked_ids(item) if isinstance(item, list) else {item}
    return out


def ordered_ids(res):
    """Nested sequence of EDGE ids (the edge that DELIVERS the packet to each
    hop), with SOURCE standing in for the very first hop (the originating
    host, which has no incoming edge). Using the edge id — not the device id —
    as each hop's identity is what lets hop_details() below attribute the
    right ingress/egress/security verdict to each specific visit, even when a
    device is traversed twice (see _graph()).

    Where the path forks, the branches are returned as a nested list and the
    walk resumes at the join point.

    Empty when the lookup produced no path at all (e.g. DEFAULT_GW_NOT_FOUND for
    the source): SOURCE is only meaningful if some edge leaves the origin, and
    hop_details() builds its SOURCE entry under the very same condition."""
    edges, succ, preds = _graph(res)
    start_edges = [eid for eid in edges if not preds[eid]]
    if not start_edges:
        return []
    succ[_START] = start_edges

    def reach(x):
        seen, dq = set(), deque([x])
        while dq:
            for y in succ.get(dq.popleft(), []):
                if y not in seen:
                    seen.add(y)
                    dq.append(y)
        return seen

    def escapes(cur, blocked):
        """True if some path from cur reaches the end of the graph without
        crossing `blocked` — i.e. `blocked` is not a point every packet must
        pass through."""
        dq, seen = deque([cur]), {cur}
        while dq:
            x = dq.popleft()
            nxt = succ.get(x, [])
            if not nxt:
                return True  # reached a terminal edge, having avoided `blocked`
            for y in nxt:
                if y != blocked and y not in seen:
                    seen.add(y)
                    dq.append(y)
        return False

    def join_of(cur, cands):
        """Nearest edge where the branches of the fork at `cur` merge back into a
        single line: the closest common descendant that EVERY path out of `cur`
        crosses (its immediate post-dominator).

        Being a common descendant is not enough. Two legs that both reach a
        downstream fork share that fork's branches, but a packet only takes one
        of them — treating such a branch as the join makes the trunk resume in
        the middle of a fork, and the walk below then overshoots it and repeats
        the whole shared tail once per leg.

        ponytail: re-runs a reachability scan per candidate. Path-lookup graphs
        are tens of edges, so this is fine; precompute post-dominators only if a
        genuinely large graph ever makes it slow."""
        dq, seen = deque([cur]), {cur}
        while dq:
            for y in succ.get(dq.popleft(), []):
                if y in seen:
                    continue
                seen.add(y)
                if y in cands and not escapes(cur, y):
                    return y
                dq.append(y)
        return None

    def walk(cur, stop):
        seq = []
        while cur != stop:
            nx = succ.get(cur, [])
            if not nx:
                break
            if len(nx) == 1:
                cur = nx[0]
                if cur == stop:
                    break
                seq.append(cur)
            else:
                common = set.intersection(*[{b} | reach(b) for b in nx])
                j = join_of(cur, common)
                branches = [[b] + walk(b, j) for b in nx]
                seq.append(branches)
                # A branch that forks again without reconverging runs to the end
                # of the graph, swallowing the join point. Appending j then would
                # print the whole tail a second time on the trunk.
                if j is None or j in _walked_ids(branches):
                    break
                if j == stop:
                    break  # the caller emits the join, same as the len(nx)==1 case
                seq.append(j)
                cur = j
        return seq

    return [SOURCE] + walk(_START, None)


# ---------- per-hop enrichment ----------
def _protocol(header_types, switching):
    """Header the packet was carried in at this hop — the old
    get_protocol_traces(): 'l2' wins if any chain was switching-nexthop,
    otherwise the first EVENT_HEADER_TYPE seen."""
    if switching:
        return "l2"
    return next((h for h in EVENT_HEADER_TYPE if h in header_types), "n/a")


def _decision_events(traces):
    """vrfs / security-checks / drops / protocol seen in the decision traces of
    ONE specific visit, not merged across every trace IP Fabric recorded for the
    device.

    `traces` is a list: a device with several egress choices records one trace
    per egress, all sharing the same sourcePacketId — so a dict keyed on that id
    silently keeps only the last one. That matters when the egress choices carry
    different verdicts, which is the case test_pathgraph.py's fw1 models (two
    traces, POLICY-A permit and POLICY-B deny, one sourcePacketId).

    Worth knowing if you are tempted to simplify this: on real captures the
    traces in a group have so far always agreed, so collapsing them would look
    harmless in practice. The synthetic test is the guard, not field data."""
    vrfs, secs, drops, headers = [], [], [], []
    switching = False
    for tr in traces:
        for chain in tr.trace:
            if chain.chain == CHAIN_SWITCHING:
                switching = True
            for ev in chain.events:
                t = ev.type
                if t == "table entry match" and str(getattr(ev, "table", "")).startswith(
                    "vRoute"
                ):
                    v = ev.filter.vrf
                    if v is not None and v not in vrfs:
                        vrfs.append(v)
                elif t in ("security check", "security check ignored"):
                    sev = ev.severityInfo
                    s = {
                        "type": ev.securityType,
                        "policy": ev.decidingPolicyName,
                        "rule": ev.decidingRule,
                        "result": sev.name if sev else None,
                        "severity": sev.severity if sev else None,
                        "ignored": t == "security check ignored",
                    }
                    if s not in secs:
                        secs.append(s)
                elif t == "drop packet":
                    if ev.reason not in drops:
                        drops.append(ev.reason)
                header = getattr(ev, "headerType", None)
                if header and header not in headers:
                    headers.append(header)
    return vrfs, secs, drops, _protocol(headers, switching)


def _packet_dst(values):
    """Destination values off a packet header, whichever shape the SDK gives.

    `IP.dst` is a plain `list[str]`, but `Transport.dst` is
    `list[str] | Numbers | str` — a port *range* collapses to the `Numbers` form
    (`{"numbers": [{"min": .., "max": ..}]}`), which a naive iteration walks as
    dict keys and silently yields nothing useful."""
    if values is None:
        return []
    if isinstance(values, str):
        return [values]
    if isinstance(values, list):
        return [str(v) for v in values]
    return [
        str(n.min) if n.min == n.max else f"{n.min} .. {n.max}"
        for n in getattr(values, "numbers", None) or []
    ]


def _delivered(edge):
    """What the packet looked like as it ARRIVED on this edge: destination IP(s)
    and, for tcp/udp, destination port(s).

    The terminal hop of a path reports this as what reached the destination. Inner
    headers come last in an encapsulated packet, so later wins."""
    ips, ports = [], []
    for pkt in edge.packet or []:
        if pkt.type in ("ip", "ipv6"):
            ips = _packet_dst(pkt.dst)
        elif pkt.type in ("tcp", "udp"):
            ports = _packet_dst(pkt.dst)
    return {"ips": ips, "ports": ports}


def dropped_packets(res):
    """Per-device summary of what was DROPPED: interface(s) and, for tcp/udp, the
    destination port(s).

    Reads `node.droppedPackets`, which carries only the subset actually denied —
    on a PARTIAL path that is narrower than what the hop received, which is why
    this cannot be derived from the enriched hop's `delivered`."""
    out = []
    for node in res.nodes.values():
        dropped = node.droppedPackets or {}
        if not dropped:
            continue
        ports = []
        for d in dropped.values():
            for pkt in d.packet or []:
                if pkt.type not in ("tcp", "udp"):
                    continue
                for p in _packet_dst(pkt.dst):
                    if p not in ports:
                        ports.append(p)
        out.append(
            {
                "device": " ".join(node.label.split()),
                "type": node.type,
                "ifaces": sorted({d.ifaceName or "?" for d in dropped.values()}),
                "ports": ports,
            }
        )
    return out


def _zones(zonefw_interfaces, device, ifaces):
    """ZoneFW zone(s) covering this device's interfaces (the old
    find_zonefw_interface, widened to the several egress a fork can have)."""
    if not zonefw_interfaces or not ifaces:
        return None
    zones = {
        "/".join(intf["zone"])
        for intf in zonefw_interfaces
        if intf["hostname"] == device and intf["intName"] in ifaces
    }
    return ",".join(sorted(zones)) or None


def hop_details(res, zonefw_interfaces=None):
    """Per-VISIT hop details, keyed by ordered_ids()'s edge ids / SOURCE.

    A device visited twice (e.g. a load-balancer hairpin, see _graph()) gets
    two independent entries here — each showing only the ingress/egress/
    security verdict that actually applied to THAT pass, not a blob merged
    across both. Decision traces are matched to their specific visit via
    trace.sourcePacketId, which IP Fabric sets to the exact edge id (the same
    keys as res.edges) that delivered the packet for that trace."""
    edges, succ, preds = _graph(res)
    decisions = (res.pathlookup.decisions if res.pathlookup else {}) or {}
    traces_by_edge = defaultdict(list)
    for dec in decisions.values():
        for tr in dec.traces if dec else []:
            traces_by_edge[tr.sourcePacketId].append(tr)

    def detail(node_id, ingress, egress, traces, delivered=None, terminal=False):
        node = res.nodes[node_id]
        vrfs, secs, drops, protocol = _decision_events(traces)
        blocked = bool(drops) or any(
            not s["ignored"] and (s["severity"] or 0) >= SEVERITY_RED for s in secs
        )
        return {
            # Whether the packet went no further, as a property of the GRAPH. Not
            # the same as an empty `egress`: that is only the successor edge's
            # interface name, which cloud nodes (transit, awsSubnet, awsEni) leave
            # unset while still forwarding onward.
            "terminal": terminal,
            "delivered": delivered or {"ips": [], "ports": []},
            # A host node carrying several IPs has them newline-separated in its
            # label, which would break both the tree layout and the table rows.
            "device": " ".join(node.label.split()),
            "type": node.type,
            "sn": node.sn,
            "ingress": ingress or None,
            "egress": egress or None,
            "protocol": protocol,
            "vrf": (vrfs[0] if len(vrfs) == 1 else (vrfs or None)),
            "zonefw": _zones(zonefw_interfaces, node.label, egress or []),
            "security": secs or None,
            "dropped": bool(drops),
            "drop_reason": drops[0] if drops else None,
            "blocked": blocked,
        }

    out = {}
    start_edges = [eid for eid in edges if not preds[eid]]
    if start_edges:
        start_node = edges[start_edges[0]][0]
        # ponytail: merges the egress of every start edge onto the one source hop,
        # so a source with two uplinks shows both here rather than one per branch.
        # Split per branch only if a real path makes this misleading.
        start_egress = sorted(
            {
                res.edges[se].sourceIfaceName
                for se in start_edges
                if res.edges[se].sourceIfaceName
            }
        )
        # The source is never terminal: it exists only because some edge leaves it.
        out[SOURCE] = detail(start_node, None, start_egress, [], terminal=False)
    for eid, (_, target_id) in edges.items():
        ingress = (
            [res.edges[eid].targetIfaceName] if res.edges[eid].targetIfaceName else []
        )
        egress = sorted(
            {
                res.edges[nx].sourceIfaceName
                for nx in succ.get(eid, [])
                if res.edges[nx].sourceIfaceName
            }
        )
        out[eid] = detail(
            target_id,
            ingress,
            egress,
            traces_by_edge.get(eid, []),
            _delivered(res.edges[eid]),
            terminal=not succ.get(eid),
        )
    return out


def enrich(res, zonefw_interfaces=None):
    """Nested hop structure: hop dicts in path order, forks as nested lists."""
    d = hop_details(res, zonefw_interfaces)

    def render(x):
        return [render(i) for i in x] if isinstance(x, list) else d[x]

    return render(ordered_ids(res))


def flatten(structure):
    """enrich() output -> flat ordered list of hop dicts (parallel branches inlined)."""
    return [hop for _, hop in flat_rows(structure)]


def flat_rows(structure, branch=""):
    """Like flatten(), but yields (branch marker, hop) so a flat rendering (the
    -t table) can still show which leg of a fork each hop belongs to."""
    for item in structure:
        if isinstance(item, list):
            for n, br in enumerate(item, 1):
                yield from flat_rows(br, f"{branch}↳{n}")
        else:
            yield branch, item


def destinations(structure):
    """Terminal hops — where traffic was accepted and forwarded no further.

    Not keyed on the node being a host or 'cloud' node: a path can legitimately
    terminate on an awsVpc / NAE node, which carries neither the 'cloud' type nor a
    'host-' id. On a PARTIAL path this returns only the legs that got through.

    `terminal`, not "empty egress" — an AWS path runs
    transit -> awsTgw -> awsSubnet -> awsEni -> host, and every one of those cloud
    hops leaves the successor edge's interface name unset. Testing egress reports
    all four as arrivals when only the last one is.

    `blocked`, not `dropped` — a hop denied by a red security verdict records no
    'drop packet' event, so it is blocked without being dropped. Under securedPath
    that hop is where the path ends, and it is emphatically not an arrival."""
    return [
        hop
        for hop in flatten(structure)
        if hop is not _L2_SKIP and hop["terminal"] and not hop["blocked"]
    ]


def branch_count(structure):
    """Distinct end-to-end legs: the branches of one fork add, sequential forks
    multiply (two 2-way forks in a row really are four paths)."""
    if not structure:
        return 0
    total = 1
    for item in structure:
        if isinstance(item, list):
            total *= sum(branch_count(br) for br in item)
    return total


# ---------- L2 exclusion ----------
_L2_SKIP = {
    "terminal": False,
    "delivered": {"ips": [], "ports": []},
    "device": "... l2/fp skipped ...",
    "type": "",
    "sn": None,
    "ingress": None,
    "egress": None,
    "protocol": "",
    "vrf": None,
    "zonefw": None,
    "security": None,
    "dropped": False,
    "drop_reason": None,
    "blocked": False,
}


def collapse_l2(structure):
    """Replace runs of pure L2/FabricPath hops with one placeholder. A hop that
    carries a security verdict or a drop is always kept, however it forwards."""
    out = []
    for item in structure:
        if isinstance(item, list):
            out.append([collapse_l2(br) for br in item])
            continue
        if (
            item["protocol"] in L2_EXCLUSION_PROTOCOL
            and not item["security"]
            and not item["blocked"]
        ):
            if not out or out[-1] is not _L2_SKIP:
                out.append(_L2_SKIP)
        else:
            out.append(item)
    return out


# ---------- pretty print ----------
def _io(values):
    return ",".join(values) if values else "-"


def _widths(structure):
    """Device and type only. Interface names run from 'Et1' to
    'GigabitEthernet5.public-internet', so padding them to the widest would wrap
    every line; they are left ragged inside the brackets instead."""
    hops = [h for h in flatten(structure) if h is not _L2_SKIP]
    return (
        max((len(h["device"]) for h in hops), default=0),
        max((len(h["type"]) for h in hops), default=0),
    )


def show(structure, indent=0, widths=None):
    """Print the enriched path as a tree: one line per hop, forks as labelled
    parallel branches, security/drop detail indented underneath."""
    if widths is None:
        widths = _widths(structure)
    wd, wt = widths
    pad = "  " * indent
    for hop in structure:
        if isinstance(hop, list):
            print(f"{pad}[dim]╠═ parallel:[/dim]")
            for br in hop:
                show(br, indent + 1, widths)
            continue
        if hop is _L2_SKIP:
            print(f"{pad}[dim]{hop['device']}[/dim]")
            continue
        io = f"[{_io(hop['ingress'])} → {_io(hop['egress'])}]"
        extra = f"  {hop['protocol']}" if hop["protocol"] else ""
        if hop["vrf"]:
            vrf = hop["vrf"] if isinstance(hop["vrf"], str) else ",".join(hop["vrf"])
            extra += f"  vrf={vrf}"
        if hop["zonefw"]:
            extra += f"  zone={hop['zonefw']}"
        flag = "  [red]⛔ BLOCKED[/red]" if hop["blocked"] else ""
        print(
            f"{pad}• [cyan]{hop['device']:<{wd}}[/cyan] "
            f"[dim]{hop['type']:<{wt}}[/dim] {escape(io)}[green]{escape(extra)}[/green]{flag}"
        )
        for s in hop["security"] or []:
            icon = display_severity(s["severity"])
            rule = f" rule={s['rule']}" if s["rule"] else ""
            ignored = " [dim](ignored)[/dim]" if s["ignored"] else ""
            print(
                f"{pad}     🔒 {icon} {escape(str(s['type']))} "
                f"'{escape(str(s['policy']))}'{escape(rule)} → {s['result']}{ignored}"
            )
        if hop["dropped"]:
            print(f"{pad}     [red]✗ {escape(str(hop['drop_reason']))}[/red]")


# ── Where / why is traffic blocked ────────────────────────────────────────────
def hop_state(h):
    """One-line verdict for a hop."""
    if h["blocked"]:
        if h["drop_reason"]:
            return f"⛔ {h['drop_reason']}"
        bad = [s for s in (h["security"] or []) if not s["ignored"]]
        if bad:
            return f"⛔ {bad[0]['policy']} → {bad[0]['result']}"
        return "⛔ blocked"
    if h["security"]:
        s = h["security"][0]
        return f"{display_severity(s['severity'])} {s['policy']} → {s['result']}"
    return "✓"


def blocked_hops(res, zonefw_interfaces=None):
    """Hops where the packet was denied or dropped, each with the deciding
    security rule(s). Returns a list of dicts:
        {device, type, drop_reason, denies:[{type, policy, rule, result}]}"""
    out = []
    for h in flatten(enrich(res, zonefw_interfaces)):
        if not h["blocked"]:
            continue
        denies = [
            {
                "type": s["type"],
                "policy": s["policy"],
                "rule": s["rule"],
                "result": s["result"],
            }
            for s in (h["security"] or [])
            if not s["ignored"] and (s["severity"] or 0) >= SEVERITY_RED
        ]
        out.append(
            {
                "device": h["device"],
                "type": h["type"],
                "drop_reason": h["drop_reason"],
                "denies": denies,
            }
        )
    return out


def show_blocked(res, zonefw_interfaces=None):
    """Print where/why the packet was blocked — the firewall and the deciding
    rule. Prints an all-clear line if nothing blocks the path."""
    blocks = blocked_hops(res, zonefw_interfaces)
    if not blocks:
        print("[green]✓ No blocking hop — traffic is permitted end to end.[/green]")
        return
    for b in blocks:
        print(f"[red]⛔ Traffic blocked at {b['device']} ({b['type']})[/red]")
        for s in b["denies"]:
            print(
                f"     rule: {escape(str(s['type']))} policy "
                f"'{escape(str(s['policy']))}'  rule={s['rule']}  → {s['result']}"
            )
        if b["drop_reason"]:
            print(f"     drop: {escape(str(b['drop_reason']))}")
