"""
# report.py
Writing one flow's files to a report folder:

    <name>.json           the raw IP Fabric response (usable as a golden fixture)
    <name>.png            the diagram, if requested
    <name>.md             detailed report, every branch
    <name>_summary.md     verdict + first path

The markdown is written last, so a flow with an .md is a complete flow.
"""

import json
import re
from pathlib import Path

from .lookup import DEFAULT_SRC_PORT
from .markdown import ReportData, detailed_markdown, summary_markdown
from .pathgraph import enrich


def flow_name(flow: dict, taken: set) -> str:
    """File stem for a flow, unique within `taken` (which it updates).

    `<src>_to_<dst>_<proto>[-<dstPort>][_sp<srcPort>]`, with `/` and `,` made
    filename-safe. A second flow that would get the same name (it differs only in
    something the name omits, e.g. security mode) gets `_2`, `_3`..."""
    name = f"{flow['src_ip']}_to_{flow['dst_ip']}_{flow['protocol']}"
    if flow["protocol"] != "icmp":
        name += f"-{flow['dst_port']}"
        if flow["src_port"] != DEFAULT_SRC_PORT:
            name += f"_sp{flow['src_port']}"
    name = re.sub(r"[^A-Za-z0-9._+-]", "-", name.replace(",", "+").replace("/", "-"))
    unique, count = name, 1
    while unique in taken:
        count += 1
        unique = f"{name}_{count}"
    taken.add(unique)
    return unique


def fingerprint(
    flow: dict, snapshot_id: str, auto_pivot: bool, security_detail: bool = False
) -> str:
    """Everything that decides what a flow's files contain. It is written into the
    .md, and `load_saved_flow()` only trusts saved files whose fingerprint matches
    the current run — so a changed snapshot, security mode or application is not
    silently resumed from stale files."""
    keys = (
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "secured_path",
        "application",
    )
    wanted = {k: flow.get(k) for k in keys} | {
        "snapshot": snapshot_id,
        "auto_pivot": auto_pivot,
        "security_detail": security_detail,
    }
    return json.dumps(wanted, sort_keys=True)


def load_saved_flow(out_dir: Path, name: str, fingerprint_: str, need_png: bool):
    """A finished flow from an earlier run, as (outcome, pivot note), or None if it is
    missing, incomplete (no .md: the .md is written last), made for different
    parameters, or lacks the PNG this run wants. The outcome is the verdict as it was
    computed then (see markdown.detailed_markdown)."""
    md, raw = out_dir / f"{name}.md", out_dir / f"{name}.json"
    if not (md.exists() and raw.exists()):
        return None
    if need_png and not (out_dir / f"{name}.png").exists():
        return None
    text = md.read_text()
    outcome = re.search(r"^<!-- outcome: (.*) -->$", text, re.M)
    if f"<!-- flow: {fingerprint_} -->" not in text or not outcome:
        return None
    pivot = re.search(r"^\| Pivot \| (.*) \|$", text, re.M)
    return json.loads(outcome.group(1)), pivot.group(1) if pivot else ""


def write_flow_report(
    out_dir: Path,
    name: str,
    flow: dict,
    lookup,
    outcome: dict,
    zonefw_interfaces,
    extra: dict | None = None,
    png: bytes | None = None,
    fingerprint_: str | None = None,
    rules: dict | None = None,
) -> str:
    """Write the flow's files into `out_dir` (created if needed); returns the .md name."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.json").write_text(
        json.dumps(lookup.raw, indent=1, sort_keys=True)
    )
    if png:
        (out_dir / f"{name}.png").write_bytes(png)

    data = ReportData(
        name=name,
        flow=flow,
        outcome=outcome,
        result=lookup.result,
        structure=enrich(lookup.result, zonefw_interfaces, rules),
        zonefw_interfaces=zonefw_interfaces,
        rules=rules,
        extra=extra or {},
        image=f"{name}.png" if png else None,
        fingerprint=fingerprint_,
    )
    (out_dir / f"{name}_summary.md").write_text(summary_markdown(data))
    (out_dir / f"{name}.md").write_text(detailed_markdown(data))
    return f"{name}.md"
