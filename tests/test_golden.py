"""
# Golden-file check — "does this still produce what it produced last time?"

The idea, in one line: run our functions over a RECORDED path lookup, render the
result as text, and compare it to a committed copy of that text. If they differ,
either we changed the code or something underneath us changed — and the diff says
exactly what. No pytest, no framework; it is a `diff` with extra steps.

Why this exists: `test_pathgraph.py` proves the walk is correct on SYNTHETIC data
we wrote ourselves, so it can never notice that IP Fabric started returning a new
node type or that the SDK changed a model. This one runs on REAL responses, so it
does.

    python tests/test_golden.py            # compare — this is the check
    python tests/test_golden.py --update   # accept the current output as correct
    python tests/test_golden.py --record   # re-fetch the responses from a live server

## When you upgrade the SDK

    pip install -U ipfabric && python tests/test_golden.py

A clean run means the upgrade changed nothing we depend on. A diff is the upgrade's
effect on our output, spelled out line by line. If the new output is right, accept
it with `--update` and commit — the diff in code review IS the record of what the
upgrade did.

## When you upgrade IP Fabric

Same, but re-fetch first, because the responses themselves change:

    python tests/test_golden.py --record    # needs .env, read-only, no writes
    git diff tests/fixtures/                # what IP Fabric now returns
    python tests/test_golden.py             # what that did to our output

Keeping the two steps separate matters: `git diff` on the .json shows what THEY
changed, the failing comparison shows what it did to US.
"""

import argparse
import difflib
import io
import json
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path

# Pin rich's output BEFORE anything imports it: the global console reads these at
# construction, and `modules` pulls rich in. Without this the captured tree carries
# ANSI colour codes when stdout is a terminal and not when it is piped — so the
# saved expectation would depend on how you happened to run the script.
os.environ["NO_COLOR"] = "1"
os.environ["TERM"] = "dumb"
os.environ["COLUMNS"] = "120"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipfabric.diagrams.output_models import PathLookupResult
from rich import get_console

from modules.pathdiff import (
    diff_paths,
    divergence_point,
    overlay_diff,
    overlay_hops,
    overlay_path_devices,
    path_devices,
    show_overlay,
)
from modules.pathgraph import (
    blocked_hops,
    collapse_l2,
    destinations,
    enrich,
    flat_rows,
    show,
)
from modules.pivot import return_entry_point_pivot
from modules.verdict import classify

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Each scenario is one recorded lookup. `flow` is only used by --record; the saved
# .json is what the comparison actually runs on, so the check works with no server.
# The workshop flow: Prague client -> APP-A. Day 1 reaches it via Boston, Day 4 is
# after the Paris fix + SD-WAN migration, so the path genuinely differs.
WORKSHOP_FLOW = {"srcIP": "172.16.11.60", "dstIP": "172.16.39.10",
                 "dstPort": "443", "protocol": "tcp"}

SCENARIOS = [
    {
        "name": "site2-to-aws-ping",
        "why": "long path, L2 runs, ECMP forks — the original workshop capture",
        "flow": None,  # recorded by hand, no flow definition to replay
    },
    {
        "name": "workshop-day1",
        "why": "same flow as day 4, on the Day 1 snapshot — the 'before'",
        "flow": WORKSHOP_FLOW,
        "snapshot": "SNAP_DAY1",
    },
    {
        "name": "workshop-day4",
        "why": "same flow as day 1, after the Paris fix + SD-WAN migration",
        "flow": WORKSHOP_FLOW,
        "snapshot": "SNAP_DAY4",
    },
    {
        "name": "workshop-day1-vs-day4-overlay",
        "why": "IP Fabric's server-side compare overlay; the only input "
               "overlay_hops / overlay_diff / divergence_point can run on",
        "flow": WORKSHOP_FLOW,
        "snapshot": "SNAP_DAY1",          # base
        "compare_to": "SNAP_DAY4",        # overlay
        "render": "overlay",
    },
    {
        "name": "rdp-blocked-zonefw",
        "why": "BLOCKED by a zone firewall; exercises droppedPackets + deciding rule",
        "flow": {"srcIP": "172.16.12.60/24", "dstIP": "172.16.23.20",
                 "dstPort": "3389", "protocol": "tcp", "application": "rdp"},
    },
    {
        "name": "rdp-partial-subnet",
        "why": "PARTIAL: one host of the subnet reached, the rest denied",
        "flow": {"srcIP": "172.16.12.60/24", "dstIP": "172.16.23.20/24",
                 "dstPort": "3389", "protocol": "tcp", "application": "rdp"},
    },
    {
        "name": "aws-cloud-path",
        "why": "cloud node types (transit/awsTgw/awsSubnet/awsEni) — these set no "
               "interface name, which is what broke destination detection once",
        "flow": {"srcIP": "172.16.12.60/24", "dstIP": "10.2.0.222",
                 "dstPort": "1024-65535", "protocol": "tcp", "application": "https"},
    },
    {
        "name": "auto-pivot-reverse",
        "why": "the reverse lookup auto-pivot runs (dst -> src): its first --transit "
               "edge is the entry point the real lookup gets pinned to",
        "flow": {"srcIP": "10.64.128.5", "dstIP": "172.15.0.1",
                 "dstPort": "3389", "protocol": "tcp"},
        "render": "pivot",
    },
    {
        "name": "auto-pivot-pinned",
        "why": "src has no default gateway; lookup pinned to the entry point found "
               "by the reverse path, and it REACHES the destination",
        "flow": {"srcIP": "172.15.0.1", "dstIP": "10.64.128.5",
                 "dstPort": "3389", "protocol": "tcp", "security": "continue"},
        "auto_pivot": True,
    },
]

# Pairs of already-recorded scenarios, compared locally. This is the only thing
# that exercises pathdiff.diff_paths — the Jupyter side of the repo, which the
# synthetic self-check never touches.
DIFFS = [
    {
        "name": "workshop-day1-vs-day4-local",
        "a": "workshop-day1",
        "b": "workshop-day4",
        "why": "local hop-aligned diff of the two snapshots (difflib alignment)",
    },
]


def render(res):
    """The recorded result as deterministic text.

    Two halves on purpose: the derived VALUES (what the CSV would say) and the
    rendered TREE (what the CLI would print). A change to either is worth seeing,
    and keeping them in one file means one diff to read."""
    out = []
    verdict = classify(res)
    out.append("== verdict ==")
    for key in ("status", "details", "blocked_at", "rule", "branches"):
        out.append(f"{key}: {verdict[key]}")

    path = enrich(res)
    out.append("\n== destinations ==")
    for hop in destinations(path) or []:
        delivered = hop["delivered"]
        out.append(f"{hop['device']} [{hop['type']}] "
                   f"ips={delivered['ips']} ports={delivered['ports']}")

    out.append("\n== blocked hops ==")
    for block in blocked_hops(res) or []:
        out.append(f"{block['device']} [{block['type']}] drop={block['drop_reason']}")
        for deny in block["denies"]:
            out.append(f"    {deny['type']} '{deny['policy']}' "
                       f"rule={deny['rule']} -> {deny['result']}")

    out.append("\n== hops ==")
    for branch, hop in flat_rows(path):
        out.append(f"{branch or '-':6} {hop['device']} [{hop['type']}] "
                   f"in={hop['ingress']} out={hop['egress']} proto={hop['protocol']} "
                   f"vrf={hop['vrf']} blocked={hop['blocked']} terminal={hop['terminal']}")

    for label, structure in (("tree", path), ("tree --l2", collapse_l2(path))):
        out.append(f"\n== {label} ==")
        out.append(_capture(show, structure))

    return "\n".join(out) + "\n"


def _capture(fn, *args):
    """Run a printing helper and return its text, at a pinned width."""
    console = get_console()
    previous_width = console.width
    console.width = 120
    buffer = io.StringIO()
    try:
        with redirect_stdout(buffer):
            fn(*args)
    finally:
        console.width = previous_width
    return buffer.getvalue().rstrip()


def render_pivot(res):
    """A normal render, plus the entry point auto-pivot would extract from it."""
    return render(res) + f"\n== entry point ==\n{return_entry_point_pivot(res)}\n"


def render_overlay(res):
    """A server-side compare overlay as text.

    Covers the half of pathdiff that needs IP Fabric to do the comparing:
    which hops were added/removed between the snapshots, and where the two paths
    first diverge."""
    out = ["== divergence point =="]
    out.append(str(divergence_point(res)))
    out.append("\n== devices (base / compare) ==")
    out.append(str(overlay_path_devices(res)))
    out.append("\n== overlay diff ==")
    # to_csv, not to_string: pandas' column padding shifts between versions and
    # would show up as a spurious diff in every cell.
    out.append(overlay_diff(res, "day1", "day4").to_csv(index=False).rstrip())
    out.append("\n== overlay tree ==")
    out.append(_capture(show_overlay, overlay_hops(res)))
    return "\n".join(out) + "\n"


def render_diff(res_a, res_b, name_a, name_b):
    """Two independently-recorded lookups, diffed locally (difflib alignment)."""
    out = [f"== devices: {name_a} ==", str(path_devices(res_a)),
           f"\n== devices: {name_b} ==", str(path_devices(res_b)),
           f"\n== diff_paths({name_a}, {name_b}) =="]
    out.append(diff_paths(res_a, res_b, name_a, name_b).to_csv(index=False).rstrip())
    return "\n".join(out) + "\n"


def load(name):
    return PathLookupResult(**json.loads((FIXTURES / f"{name}.json").read_text()))


def record():
    """Re-fetch every scenario's response from a live server into fixtures/.

    Read-only: path lookups only, nothing is created. Needs the usual .env, plus
    SNAP_DAY1 / SNAP_DAY4 for the workshop scenarios — those are skipped with a
    note if unset, so this still works against any instance."""
    import os

    from dotenv import find_dotenv, load_dotenv

    from e2e_analysis import _client
    from modules.lookup import flow_from_row, run_lookup, unicast_from_row

    # Load .env up front: the snapshot lookups below happen before _client() would
    # otherwise do it, and unset vars silently skip scenarios.
    load_dotenv(find_dotenv(), override=True)

    for scenario in SCENARIOS:
        name = scenario["name"]
        if not scenario["flow"]:
            print(f"  {name}: hand-recorded, skipping")
            continue

        snapshot = os.getenv(scenario.get("snapshot") or "", "")
        if scenario.get("snapshot") and not snapshot:
            print(f"  {name}: SKIPPED — ${scenario['snapshot']} not set")
            continue

        kwargs = {}
        if scenario.get("compare_to"):
            compare = os.getenv(scenario["compare_to"], "")
            if not compare:
                print(f"  {name}: SKIPPED — ${scenario['compare_to']} not set")
                continue
            # A compare overlay derives its base from the client's snapshot, and
            # the SDK raises if snapshot_id is passed as well — so the base goes
            # on the client, not in kwargs.
            kwargs["overlay"] = {"snapshotToCompare": compare}

        client = _client(snapshot)
        if scenario.get("auto_pivot"):
            # The real path: plain lookup, reverse lookup, lookup pinned to the entry
            # point. We keep the Unicast that produced the final result.
            lookup = run_lookup(
                client.diagram, flow_from_row(scenario["flow"]), auto_pivot=True
            )
            unicast = lookup.unicast
        else:
            unicast = unicast_from_row(scenario["flow"])
        data = client.diagram.json(unicast, **kwargs)
        path = FIXTURES / f"{name}.json"
        path.write_text(json.dumps(data, indent=1, sort_keys=True))
        print(f"  {name}: {path.stat().st_size // 1024} KB")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--update", action="store_true",
                        help="accept the current output as the new expectation")
    parser.add_argument("--record", action="store_true",
                        help="re-fetch responses from a live server (read-only)")
    args = parser.parse_args()

    if args.record:
        print("recording from live server:")
        record()
        print("\nnow run without --record to see what changed.")
        return 0

    # Each entry is (name, callable producing the rendered text). Diffs come last
    # because they read two recordings that the loop above must find on disk.
    cases = [
        (s["name"], (lambda s=s: {"overlay": render_overlay, "pivot": render_pivot}
                     .get(s.get("render"), render)(load(s["name"]))))
        for s in SCENARIOS
        if (FIXTURES / f"{s['name']}.json").exists()
    ]
    missing = [s["name"] for s in SCENARIOS
               if not (FIXTURES / f"{s['name']}.json").exists()]
    for name in missing:
        print(f"?  {name}: no recording yet — run --record")

    for pair in DIFFS:
        if pair["a"] in missing or pair["b"] in missing:
            print(f"?  {pair['name']}: needs {pair['a']} + {pair['b']} recorded")
            continue
        cases.append((pair["name"], lambda p=pair: render_diff(
            load(p["a"]), load(p["b"]), p["a"], p["b"])))

    failed = []
    for name, build in cases:
        actual = build()
        expected_path = FIXTURES / f"{name}.expected.txt"

        if args.update or not expected_path.exists():
            expected_path.write_text(actual)
            print(f"++ {name}: expectation written ({len(actual.splitlines())} lines)")
            continue

        expected = expected_path.read_text()
        if actual == expected:
            print(f"OK {name}")
            continue

        failed.append(name)
        print(f"\nXX {name} — output changed:")
        print("".join(difflib.unified_diff(
            expected.splitlines(keepends=True), actual.splitlines(keepends=True),
            fromfile=f"{name}.expected.txt", tofile="now", n=2)))

    if failed:
        print(f"\n{len(failed)} scenario(s) changed: {', '.join(failed)}")
        print("If the new output is CORRECT, run --update and commit the diff.")
        return 1
    print("\ngolden check OK — output unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
