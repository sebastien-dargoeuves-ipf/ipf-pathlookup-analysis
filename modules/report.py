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


def write_flow_report(
    out_dir: Path,
    name: str,
    flow: dict,
    lookup,
    outcome: dict,
    zonefw_interfaces,
    extra: dict | None = None,
    png: bytes | None = None,
) -> str:
    """Write the flow's files into `out_dir` (created if needed); returns the .md name."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.json").write_text(json.dumps(lookup.raw, indent=1, sort_keys=True))
    if png:
        (out_dir / f"{name}.png").write_bytes(png)

    data = ReportData(
        name=name,
        flow=flow,
        outcome=outcome,
        result=lookup.result,
        structure=enrich(lookup.result, zonefw_interfaces),
        zonefw_interfaces=zonefw_interfaces,
        extra=extra or {},
        image=f"{name}.png" if png else None,
    )
    (out_dir / f"{name}_summary.md").write_text(summary_markdown(data))
    (out_dir / f"{name}.md").write_text(detailed_markdown(data))
    return f"{name}.md"
