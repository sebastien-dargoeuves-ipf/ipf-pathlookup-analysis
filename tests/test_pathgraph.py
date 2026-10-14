r"""
Self-check for modules/pathgraph.py — run it with `python test_pathgraph.py`.
No pytest, no server: it builds a synthetic PathLookupResult that reproduces the
three things the old walk got wrong, and asserts the new one gets them right.

Topology (a fork at the end, and sw1 traversed twice via a load-balancer hairpin):

    h1 -e1-> sw1 -e2-> fw1 -e3-> lb1 -e4-> sw1 -e5-> h2
                                              \-e6-> h3
"""

import sys
from pathlib import Path

# This file lives in tests/, but `modules/` sits one level up in the repo root.
# Running `python tests/test_pathgraph.py` puts tests/ on sys.path, not the root,
# so `import modules` would fail. Add the root ourselves and it works from any
# directory, with no PYTHONPATH and no `-m` incantation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipfabric.diagrams.output_models import PathLookupResult

from modules.pathgraph import (
    branch_count,
    collapse_l2,
    destinations,
    enrich,
    flat_rows,
    flatten,
)
from modules.pivot import return_entry_point_pivot
from modules.verdict import classify, evaluate_expectation, expected_passing_traffic

CHECKS = {"0": 0, "10": 0, "20": 0, "30": 0}
SCORE = {"accepted": 1, "dropped": 0, "forwarded": 1, "total": 1}
SETTINGS_ID = "00000000-0000-0000-0000-000000000000"


def _node(nid, label, ntype):
    return {"children": [], "graphType": "pathLookup", "id": nid,
            "label": label, "sn": f"sn-{label}", "type": ntype}


def _edge(eid, source, target, src_iface, dst_iface, nxt, prev, packet=None):
    return {"direction": "forward", "source": source, "target": target,
            "edgeSettingsId": SETTINGS_ID, "id": eid, "labels": {},
            "nextEdgeIds": nxt, "prevEdgeIds": prev, "packet": packet or [],
            "severityInfo": CHECKS, "sourceIfaceName": src_iface,
            "targetIfaceName": dst_iface, "trafficScore": SCORE}


def _tcp(dst_ip, dst_port):
    """An ip+tcp packet as it arrives on an edge — what `delivered` reads."""
    return [{"type": "ip", "src": ["10.0.0.1"], "dst": [dst_ip], "protocol": "tcp"},
            {"type": "tcp", "src": ["1024"], "dst": dst_port, "flags": []}]


def _dropped(iface, dst_port):
    """A node's droppedPackets entry: only the subset actually denied."""
    return {"d1": {"ifaceName": iface,
                   "packet": [{"type": "tcp", "src": ["1024"],
                               "dst": dst_port, "flags": []}]}}


def _security(policy, severity, name):
    return {"type": "security check", "protocolId": "tcp", "securityType": "zonefw",
            "decidingPolicyName": policy, "decidingRule": [1],
            "severityInfo": {"name": name, "severity": severity, "topic": "ZONEFW"}}


def _trace(chain, events, src, dst):
    return {"severityInfo": CHECKS, "sourcePacketId": src, "targetPacketId": dst,
            "trace": [{"chain": chain, "phase": "core", "events": events}]}


def build(deny=False):
    """Synthetic result. `deny` flips fw1's second policy to a red verdict, and
    with it the whole outcome: no traffic passes and fw1 records a drop."""
    e1, e2 = "e1--h1--sw1", "e2--sw1--fw1"
    e3, e4 = "e3--fw1--lb1", "e4--lb1--sw1"
    e5, e6 = "e5--sw1--h2", "e6--sw1--h3"
    ip_header = {"type": "patch header", "patch": {"ttl": 63}, "index": 0,
                 "headerType": "ip"}
    edges = {
        e1: _edge(e1, "h1", "sw1", "-", "Et1", [e2], []),
        e2: _edge(e2, "sw1", "fw1", "Et2", "port1", [] if deny else [e3], [e1]),
        e3: _edge(e3, "fw1", "lb1", "port2", "Vl1", [e4], [e2]),
        e4: _edge(e4, "lb1", "sw1", "Vl100", "Et3", [e5, e6], [e3]),
        e5: _edge(e5, "sw1", "h2", "Et4", "-", [], [e4], _tcp("10.0.9.60", ["3389"])),
        e6: _edge(e6, "sw1", "h3", "Et5", "-", [], [e4],
                  _tcp("10.0.9.61", ["3389", "443"])),
    }
    if deny:
        # securedPath: a denied packet stops at the firewall. Leaving the downstream
        # edges in place would model traffic that both was denied and arrived.
        for dead in (e3, e4, e5, e6):
            del edges[dead]
    return PathLookupResult(
        graphResult={
            "boxLabels": {},
            "settings": {},
            "graphData": {
                "nodes": {
                    "h1": _node("h1", "host-10.0.0.1", "cloud"),
                    "sw1": _node("sw1", "sw1", "switch"),
                    "fw1": _node("fw1", "fw1", "fw") | (
                        {"droppedPackets": _dropped("port2", ["3389"])} if deny else {}
                    ),
                    "lb1": _node("lb1", "lb1", "lb"),
                    "h2": _node("h2", "host-10.0.9.60", "cloud"),
                    "h3": _node("h3", "host-10.0.9.61", "cloud"),
                },
                "edges": edges,
            },
        },
        pathlookup={
            "eventsSummary": {"flags": [], "global": [],
                              "topics": {"ACL": CHECKS, "FORWARDING": CHECKS,
                                         "ZONEFW": CHECKS}},
            "passingTraffic": "none" if deny else "all",
            "check": {"exists": True},
            "decisions": {
                # sw1 twice: one decision per visit, keyed by the ingress edge.
                "sw1": {"traces": [
                    _trace("switching-nexthop", [], e1, e2),
                    _trace("switching-nexthop", [], e4, e5),
                ]},
                # fw1: TWO traces sharing one sourcePacketId (one per egress
                # choice) with different policies — the case a dict keyed on
                # sourcePacketId silently collapses to one.
                "fw1": {"traces": [
                    _trace("policy", [ip_header, _security("POLICY-A", 0, "PERMIT")],
                           e2, e3),
                    _trace("policy", [ip_header,
                                      _security("POLICY-B", 30 if deny else 0,
                                                "DENY" if deny else "PERMIT")],
                           e2, e3),
                ]},
                "lb1": {"traces": [_trace("policy", [ip_header], e3, e4)]},
            },
        },
    )


def as_model(res):
    """Mimic what Diagram.model() does after parsing: replace each edge's
    source/target node-id string with the Node object itself. The --file replay
    never does this, so both shapes have to work."""
    for edge in res.edges.values():
        edge.source = res.nodes[edge.source]
        edge.target = res.nodes[edge.target]
    return res


def build_empty():
    """A lookup that found no path at all — e.g. DEFAULT_GW_NOT_FOUND for the
    source. IP Fabric still returns an events summary, but zero edges."""
    res = build()
    res.graphResult.graphData.edges = {}
    return res


def build_pivot():
    """A pivot lookup whose path leaves the fabric. The '--transit' edge is what
    return_entry_point_pivot() locates the source's entry point from."""
    res = build()
    edges = res.graphResult.graphData.edges
    edges["e5--sw1--transit--#0"] = edges.pop("e5--sw1--h2")
    return res


def build_rejoin():
    r"""A fork whose legs REJOIN, then share a tail — the shape of a pair of
    edge routers feeding one core router:

        h1 -eA-> sw1 =eB1=> rtr@Et1 =eC1=> core -eD-> fw1 -eE-> h2
                     =eB2=> rtr@Et2 =eC2=>

    eB1/eB2 are two visits of rtr; both list eC1 AND eC2 as next, and eC1/eC2
    both lead to the single edge eD. eC1 is therefore a common descendant of
    both legs but NOT a join (a packet takes eC1 or eC2, never both) — eD is.
    Picking eC1 makes the trunk resume mid-fork and the shared tail print twice.
    """
    eA, eB1, eB2 = "eA--h1--sw1", "eB1--sw1--rtr", "eB2--sw1--rtr"
    eC1, eC2 = "eC1--rtr--core", "eC2--rtr--core"
    eD, eE = "eD--core--fw1", "eE--fw1--h2"
    nodes = {n: _node(n, n, t) for n, t in
             [("h1", "cloud"), ("sw1", "switch"), ("rtr", "router"),
              ("core", "router"), ("fw1", "fw"), ("h2", "cloud")]}
    return PathLookupResult(
        graphResult={
            "boxLabels": {}, "settings": {},
            "graphData": {"nodes": nodes, "edges": {
                eA: _edge(eA, "h1", "sw1", "-", "Et0", [eB1, eB2], []),
                eB1: _edge(eB1, "sw1", "rtr", "Et1", "Et1", [eC1, eC2], [eA]),
                eB2: _edge(eB2, "sw1", "rtr", "Et2", "Et2", [eC1, eC2], [eA]),
                eC1: _edge(eC1, "rtr", "core", "Et3", "Et3", [eD], [eB1, eB2]),
                eC2: _edge(eC2, "rtr", "core", "Et4", "Et4", [eD], [eB1, eB2]),
                eD: _edge(eD, "core", "fw1", "Et5", "Et5", [eE], [eC1, eC2]),
                eE: _edge(eE, "fw1", "h2", "Et6", "-", [], [eD],
                          _tcp("10.0.9.60", ["443"])),
            }},
        },
        pathlookup={
            "eventsSummary": {"flags": [], "global": [],
                              "topics": {"ACL": CHECKS, "FORWARDING": CHECKS,
                                         "ZONEFW": CHECKS}},
            "passingTraffic": "all", "check": {"exists": True}, "decisions": {},
        },
    )


def demo():
    # A fork that rejoins: everything past the merge point belongs on the trunk,
    # rendered ONCE. Before the post-dominator fix the whole tail was repeated
    # inside each leg.
    devices = [h["device"] for h in flatten(enrich(build_rejoin()))]
    assert devices.count("fw1") == 1, devices
    assert devices.count("h2") == 1, devices
    assert devices.count("rtr") == 2, devices  # two visits, one per leg
    # core is reached by eC1/eC2, which BOTH legs list as next — so that inner
    # fork is genuinely rendered under each leg. Redundant-looking but faithful.
    assert devices.count("core") == 4, devices

    # Pivot entry point, in BOTH endpoint shapes — res.nodes is keyed by id, so
    # indexing it with a Node (what Diagram.model() leaves behind) is a TypeError.
    for res in (build_pivot(), as_model(build_pivot())):
        entry = return_entry_point_pivot(res)
        assert entry == {"sn": "sn-sw1", "iface": "Et4", "hostname": "sw1"}, entry

    # No path: empty walk, not a KeyError on the SOURCE sentinel.
    assert enrich(build_empty()) == [], enrich(build_empty())

    # Both endpoint shapes must produce an identical walk (see pathgraph.node_id).
    raw = [h["device"] for h in flatten(enrich(build()))]
    modelled = [h["device"] for h in flatten(enrich(as_model(build())))]
    assert raw == modelled, (raw, modelled)

    hops = flatten(enrich(build()))
    devices = [h["device"] for h in hops]

    # 1. The fork is kept: BOTH terminal hosts are reached, not just the first.
    assert "host-10.0.9.60" in devices, devices
    assert "host-10.0.9.61" in devices, devices

    # 2. Per-visit attribution: sw1 is traversed twice, with different interfaces.
    sw1 = [h for h in hops if h["device"] == "sw1"]
    assert len(sw1) == 2, sw1
    assert sw1[0]["ingress"] == ["Et1"] and sw1[0]["egress"] == ["Et2"], sw1[0]
    assert sw1[1]["ingress"] == ["Et3"] and sw1[1]["egress"] == ["Et4", "Et5"], sw1[1]

    # 3. Both traces sharing one sourcePacketId are kept, not just the last.
    fw1 = next(h for h in hops if h["device"] == "fw1")
    assert {s["policy"] for s in fw1["security"]} == {"POLICY-A", "POLICY-B"}, fw1

    # Protocol comes from the traces: switching-nexthop -> l2, header -> ip.
    assert sw1[0]["protocol"] == "l2", sw1[0]
    assert fw1["protocol"] == "ip", fw1

    # Branch markers survive flattening, so the -t table can show which leg.
    branches = {h["device"]: b for b, h in flat_rows(enrich(build()))}
    assert branches["host-10.0.9.60"] == "↳1", branches
    assert branches["host-10.0.9.61"] == "↳2", branches
    assert branches["fw1"] == "", branches

    # A red security verdict blocks the hop; a green one does not.
    assert not fw1["blocked"], fw1
    denied = next(h for h in flatten(enrich(build(deny=True))) if h["device"] == "fw1")
    assert denied["blocked"], denied

    # ZoneFW enrichment matches on device + egress interface.
    zoned = flatten(enrich(build(), [{"hostname": "fw1", "intName": "port2",
                                      "zone": ["TRUST"]}]))
    assert next(h for h in zoned if h["device"] == "fw1")["zonefw"] == "TRUST", zoned

    # -l2 collapses the pure-switching hop but never one carrying a verdict.
    collapsed = [h["device"] for h in flatten(collapse_l2(enrich(build())))]
    assert "... l2/fp skipped ..." in collapsed, collapsed
    assert "fw1" in collapsed, collapsed

    # ── delivered packet / destinations ──────────────────────────────────────
    # The terminal hops report the IP:port that actually arrived, read off the
    # edge that delivered it — not off the node label.
    ends = destinations(enrich(build()))
    assert {tuple(h["delivered"]["ips"]) for h in ends} == {
        ("10.0.9.60",), ("10.0.9.61",)}, ends
    assert next(h for h in ends if h["delivered"]["ips"] == ["10.0.9.61"]
                )["delivered"]["ports"] == ["3389", "443"], ends
    # An intermediate hop is never a destination, however much it forwards.
    assert "fw1" not in [h["device"] for h in ends], ends
    # Nor is the SOURCE, which exists only because an edge leaves it.
    assert "host-10.0.0.1" not in [h["device"] for h in ends], ends

    # Interface names are NOT what makes a hop terminal. An AWS path runs
    # transit -> awsTgw -> awsSubnet -> awsEni -> host with no sourceIfaceName on
    # any of those edges; testing "empty egress" calls every one an arrival.
    # Strip every interface name and the answer must not budge.
    no_iface = build()
    for edge in no_iface.edges.values():
        edge.sourceIfaceName = None
    still = [h["device"] for h in destinations(enrich(no_iface))]
    assert still == ["host-10.0.9.60", "host-10.0.9.61"], still
    # A dropping hop is not a destination either — it is the opposite of one.
    assert destinations(enrich(build(deny=True))) == [], "drop is not an arrival"

    # Branches: one fork of two legs = two distinct end-to-end paths.
    assert branch_count(enrich(build())) == 2, branch_count(enrich(build()))
    # 2 outer legs, each containing the shared inner fork of 2 — the same 4 that
    # makes 'core' appear four times above.
    assert branch_count(enrich(build_rejoin())) == 4, branch_count(
        enrich(build_rejoin()))
    assert branch_count([]) == 0, "no path, no legs"

    # ── classify() ───────────────────────────────────────────────────────────
    ok = classify(build())
    assert ok["status"] == "REACHED", ok
    assert "10.0.9.60:3389" in ok["details"], ok
    assert ok["blocked_at"] == "" and ok["rule"] == "", ok
    # The source subnet is not something the traffic "reached".
    assert "10.0.0.1" not in ok["details"], ok

    # ECMP delivers to the same host once per leg; say so once, not once per leg.
    reached = classify(build_rejoin())["details"]
    assert reached.count("10.0.9.60:443") == 1, reached

    bad = classify(build(deny=True))
    assert bad["status"] == "BLOCKED", bad
    # The details name the dropping device, its interface and the denied port —
    # read from droppedPackets, which carries only the subset actually denied.
    assert "fw1 [fw] on port2 (ports: 3389)" in bad["details"], bad
    assert bad["blocked_at"] == "fw1 [fw]", bad
    assert "POLICY-B" in bad["rule"] and "DENY" in bad["rule"], bad

    # No path at all is NO-PATH, not BLOCKED: nothing denied it, nothing routed it.
    # build_empty() still carries passingTraffic="all" from build(), so this also
    # pins the guard that an edgeless graph cannot be REACHED whatever the field says.
    empty = classify(build_empty())
    assert empty["status"] == "NO-PATH", empty

    # ── intent ───────────────────────────────────────────────────────────────
    # A full outcome satisfies its intent; PARTIAL satisfies neither.
    for expected, status, want in [
        ("allow", "REACHED", "MATCH"), ("allow", "PARTIAL", "MISMATCH"),
        ("allow", "BLOCKED", "MISMATCH"), ("block", "BLOCKED", "MATCH"),
        ("block", "NO-PATH", "MATCH"), ("block", "REACHED", "MISMATCH"),
        ("block", "PARTIAL", "MISMATCH"), ("part", "PARTIAL", "MATCH"),
        ("assess", "BLOCKED", "ASSESS"), ("", "REACHED", ""),
        ("nonsense", "REACHED", "?"), ("allow", "ERROR", "n/a"),
        # Synonyms are one shared vocabulary now, not two diverging ones.
        ("permitted", "REACHED", "MATCH"), ("deny", "BLOCKED", "MATCH"),
    ]:
        got = evaluate_expectation(expected, status)
        assert got == want, (expected, status, got, want)

    # Creatable intents map to IP Fabric's expectedPassingTraffic...
    assert expected_passing_traffic("allow") == "all"
    assert expected_passing_traffic("deny") == "none"
    assert expected_passing_traffic("partial") == "part"
    # ...and the two non-assertions are NOT creatable. An empty cell must never
    # become a silent "must fully pass" verification nobody asked for.
    assert expected_passing_traffic("") is None, "empty must not default to all"
    assert expected_passing_traffic("assess") is None, "assess asserts nothing"
    assert expected_passing_traffic("nonsense") is None

    print("pathgraph + verdict self-check OK")


if __name__ == "__main__":
    demo()
