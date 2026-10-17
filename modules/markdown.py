"""
# markdown.py
Per-flow markdown reports, built from the same enriched path as the console views:

- `detailed_markdown()`: every branch, hop by hop, with the security events.
- `summary_markdown()`: the verdict and the first path on one line.

Pure text in, text out: nothing here touches the API or the disk (see `report.py`).
"""

from typing import NamedTuple

from .pathgraph import blocked_hops, note_text, path_rows
from .utilis import SEVERITY_WORD


class ReportData(NamedTuple):
    """Everything one flow's report needs.

    `extra` is ordered {label: value} for the overview (intent, verdict, pivot...);
    empty values are skipped. `image` is the PNG file name, if one was written."""

    name: str
    flow: dict
    outcome: dict
    result: object
    structure: list
    zonefw_interfaces: object
    extra: dict
    image: str | None


def _cell(value) -> str:
    """Text safe for a markdown table cell."""
    return str(value if value not in (None, "") else "").replace("|", "\\|")


def _title(data: ReportData) -> str:
    f = data.flow
    port = "" if f["protocol"] == "icmp" else f"/{f['dst_port']}"
    return f"{f['src_ip']} → {f['dst_ip']} ({f['protocol']}{port})"


def _security_events(hop) -> list[str]:
    """One line per security event on a hop, plus its drop reason."""
    lines = []
    for s in hop["security"] or []:
        rule = f" rule={s['rule']}" if s["rule"] else ""
        ignored = " (ignored)" if s["ignored"] else ""
        word = SEVERITY_WORD.get(s["severity"], "?")
        lines.append(f"{word}: {s['type']} '{s['policy']}'{rule} → {s['result']}{ignored}")
    if hop["dropped"]:
        lines.append(f"DROP: {hop['drop_reason']}")
    return lines


def _vrf(hop) -> str:
    vrf = hop["vrf"]
    return vrf if isinstance(vrf, str) else ",".join(vrf or [])


def _path_table(structure, first_only=False) -> list[str]:
    """The path as a markdown table; fork / branch / rejoin notes become italic rows
    and branch hops are indented in the Device column."""
    lines = [
        "| # | Device | Type | Ingress | Egress | Protocol | VRF | Zone | Security |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    number = 0
    for depth, hop in path_rows(structure, first_only=first_only):
        indent = "&nbsp;&nbsp;" * depth
        if isinstance(hop, tuple):
            lines.append(f"| | {indent}*{note_text(hop)}* | | | | | | | |")
            continue
        number += 1
        security = "<br>".join(_security_events(hop))
        if hop["blocked"] and not security:
            security = "BLOCKED"
        cells = [
            number,
            f"{indent}{hop['device']}",
            hop["type"],
            ",".join(hop["ingress"] or ["-"]),
            ",".join(hop["egress"] or ["-"]),
            hop["protocol"],
            _vrf(hop),
            hop["zonefw"],
            security,
        ]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return lines


def detailed_markdown(data: ReportData) -> str:
    """Every branch, hop by hop, plus the verdict, events and blocked hops."""
    f, o = data.flow, data.outcome
    out = [f"# {_title(data)}", ""]
    if data.image:
        out += [f"![path]({data.image})", ""]

    out += ["## Overview", "", "| | |", "|---|---|"]
    rows = {
        "Source": f["src_ip"],
        "Destination": f["dst_ip"],
        "Protocol": f["protocol"],
        "Source port": None if f["protocol"] == "icmp" else f["src_port"],
        "Destination port": None if f["protocol"] == "icmp" else f["dst_port"],
        "Security": "stop at the first deny" if f["secured_path"] else "continue past denies",
        **data.extra,
    }
    out += [f"| {k} | {_cell(v)} |" for k, v in rows.items() if v not in (None, "")]

    out += ["", "## Result", "", f"**{o['status']}** — {o['details']}", ""]
    out.append(f"- Branches: {o['branches']}")
    if o["blocked_at"]:
        out.append(f"- Blocked at: {o['blocked_at']}")
    if o["rule"]:
        out.append(f"- Rule: {o['rule']}")

    events = data.result.pathlookup.model_dump(by_alias=True)["eventsSummary"]["global"]
    if events:
        out += ["", "## Global events", ""]
        for e in events:
            word = SEVERITY_WORD.get(e["severity"], "?")
            out.append(f"- {word}: {e['name']} | {' | '.join(e['details'])}")

    out += ["", "## Path (all branches)", ""]
    out += _path_table(data.structure) if data.structure else ["No path available."]

    blocked = blocked_hops(data.result, data.zonefw_interfaces)
    if blocked:
        out += ["", "## Blocked hops", ""]
        for b in blocked:
            out.append(f"- **{b['device']}** ({b['type']}): {b['drop_reason'] or 'denied'}")
            for d in b["denies"]:
                out.append(f"  - {d['type']} '{d['policy']}' rule={d['rule']} → {d['result']}")
    return "\n".join(out) + "\n"


def summary_markdown(data: ReportData) -> str:
    """The verdict and the first path on one line."""
    o = data.outcome
    devices = [
        hop["device"]
        for _, hop in path_rows(data.structure, first_only=True)
        if not isinstance(hop, tuple)
    ]
    out = [f"# {_title(data)}", "", f"**{o['status']}** — {o['details']}", ""]
    for label, value in data.extra.items():
        if value:
            out.append(f"- {label}: {_cell(value)}")
    if o["blocked_at"]:
        out.append(f"- Blocked at: {o['blocked_at']}")
    out.append(f"- Branches: {o['branches']}")
    if devices:
        out += ["", "First path: " + " → ".join(devices)]
    return "\n".join(out) + "\n"
