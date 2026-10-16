"""
# Pathlookup analysis

Two ways in:

- `single` — one flow, rendered as a tree (or a table) with the security verdict.
  Optionally pivoted through another IP to find where the source is attached.
- `bulk` — a CSV of flows, each simulated and scored against its stated intent.
  With `--create-path-verifications`, each row is also pushed into IP Fabric's Path
  Verifications table, which is the only thing in this repo that writes.
"""

import csv
import ipaddress
import json
import os
import sys
import time
from collections import Counter
from enum import Enum
from pathlib import Path

import typer
from dotenv import find_dotenv, load_dotenv
from ipfabric.diagrams.output_models import PathLookupResult
from rich import print
from rich.markup import escape
from rich.table import Table

from modules.pathgraph import collapse_l2, enrich, show, show_blocked
from modules.pathLookup import (
    build_check_payload,
    check_exists,
    create_check,
    create_ipf_client,
    display_all_edges,
    display_summary_global,
    display_summary_topics,
    display_table,
    get_pathlookup_model,
    get_zonefw_interfaces,
    model_row_auto_pivot,
    unicast_from_row,
)
from modules.verdict import (
    STATUS_MARKER,
    STATUSES,
    classify,
    evaluate_expectation,
    normalise_expected,
)

# IPF_ENV_PREFIX = "_DEMO"  # _DEMO / default to env. variables
# DEMO S02 - Day2: "12dd8c61-129c-431a-b98b-4c9211571f89"
# Azure day1: "d323b197-35bb-41e5-9a42-d4de9b38ccaa"
# IPF_SNAPSHOT_OVERWRITE = "d323b197-35bb-41e5-9a42-d4de9b38ccaa"
IPF_VERIFY_OVERWRITE = False
IPF_TIMEOUT_OVERWRITE = 20


class ProtocolChoices(str, Enum):
    """
    Enum class representing protocol choices.

    Possible values:
    - tcp: TCP protocol
    - udp: UDP protocol
    - icmp: ICMP protocol
    """

    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"


app = typer.Typer(
    add_completion=False, pretty_exceptions_enable=False, no_args_is_help=True
)


def validate_option_tcp_udp_callback(
    ctx: typer.Context, option: typer.Option, value: str
):
    """
    Callback function to validate that the option is only used with TCP or UDP protocols.

    Parameters:
    ctx (Context): The Typer context object.
    option (Option): The Typer option object.
    value (str): The value of the option.

    Returns:
    str: The validated value of the option.
    """
    if ctx.params["protocol"] not in ["tcp", "udp"]:
        print(f"ICMP protocol is selected, `{option.name}` will not be used")
    return value


def validate_range_callback(value: int, min_value: int, max_value: int):
    """
    Validate that a value is within a given range.

    Parameters:
    value (int): The value to validate.
    min_value (int): The minimum allowed value.
    max_value (int): The maximum allowed value.

    Returns:
    int: The validated value.

    Raises:
    BadParameter: If the value is not within the given range.
    """
    if value < min_value or value > max_value:
        raise typer.BadParameter(f"Value must be between {min_value} and {max_value}")
    return value


def validate_ipv4_address_or_empty(address: str):
    """
    Validate that a string is a valid IPv4 address or subnet.

    Parameters:
    address (str): The string to validate.

    Returns:
    str: The validated IPv4 address or subnet.

    Raises:
    BadParameter: If the string is not a valid IPv4 address or subnet.
    """
    if not address:
        return None
    try:
        if ipaddress.IPv4Network(address):
            return address
    except Exception as error:
        raise typer.BadParameter(error) from error


def validate_ipv4_address(address: str):
    """
    Validate that a string is a valid IPv4 address or subnet.

    Parameters:
    address (str): The string to validate.

    Returns:
    str: The validated IPv4 address or subnet.

    Raises:
    BadParameter: If the string is not a valid IPv4 address or subnet.
    """
    try:
        if ipaddress.IPv4Network(address):
            return address
    except Exception as error:
        raise typer.BadParameter(error) from error


def _client(snapshot_override: str = ""):
    """Build the IP Fabric client from .env / environment, the one auth story for
    every command here. Token wins; user/password is the fallback."""
    load_dotenv(find_dotenv(), override=True)
    ipf_env_prefix = globals().get("IPF_ENV_PREFIX", "")
    base_url = os.getenv("".join(["IPF_URL", ipf_env_prefix]))
    auth = os.getenv("".join(["IPF_TOKEN", ipf_env_prefix])) or (
        os.getenv("IPF_USERNAME"),
        os.getenv("IPF_PASSWORD"),
    )
    snapshot_id = (
        snapshot_override
        or os.getenv("IPF_SNAPSHOT_ID", globals().get("IPF_SNAPSHOT_OVERWRITE", ""))
        or None
    )
    return create_ipf_client(
        base_url=base_url,
        auth=auth,
        snapshot_id=snapshot_id,
        verify=os.getenv("IPF_VERIFY", IPF_VERIFY_OVERWRITE),
        timeout=os.getenv("IPF_TIMEOUT", IPF_TIMEOUT_OVERWRITE),
    )


@app.command()
def single(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose mode."),
    src_ip: str = typer.Option(
        "",
        "--source_ip",
        "-s",
        help="Enter Source IPv4 address or subnet",
        callback=validate_ipv4_address,
    ),
    dst_ip: str = typer.Option(
        "",
        "--destination_ip",
        "-d",
        help="Enter Destination IPv4 address or subnet",
        callback=validate_ipv4_address,
    ),
    protocol: ProtocolChoices = typer.Option(
        "icmp",
        "--protocol",
        "-p",
        help="Enter Protocol (tcp, udp, icmp)",
        case_sensitive=False,
    ),
    dst_port: str = typer.Option(
        "443",
        "--destination_port",
        "-dp",
        help="Enter Destination Ports (udp, tcp)",
        callback=validate_option_tcp_udp_callback,
    ),
    src_port: str = typer.Option(
        "1024",
        "--source_port",
        "-sp",
        help="Enter Source Ports (udp, tcp)",
        callback=validate_option_tcp_udp_callback,
    ),
    source_vrf: str = typer.Option(
        None,
        "--source_vrf",
        "-vrf",
        help="Enter the Source VRF if you don't want to use the Auto-Select option",
    ),
    ttl: int = typer.Option(
        128,
        "--ttl",
        "-ttl",
        help="Enter Time To Live (TTL)",
        callback=lambda value: validate_range_callback(value, 0, 255),
    ),
    fragment_offset: int = typer.Option(
        0,
        "--fragment_offset",
        "-fo",
        help="Enter Fragment Offset",
        callback=lambda value: validate_range_callback(value, 0, 8191),
    ),
    secured_path: bool = typer.Option(
        False,
        "--secure_path",
        "-sec",
        help="Secure the path: stop the flow when hitting security rules",
    ),
    l2_exclusion: bool = typer.Option(
        False,
        "--l2_exclusion",
        "-l2",
        help="Remove L2 from the displayed path",
    ),
    pivot: str = typer.Option(
        None,
        "--pivot",
        "-pivot",
        help="Enter Pivot IPv4 address",
        callback=validate_ipv4_address_or_empty,
    ),
    auto_pivot: bool = typer.Option(
        False,
        "--auto-pivot",
        help="On DEFAULT_GW_NOT_FOUND, reverse src/dst to find where the source is connected and retry",
    ),
    table_display: bool = typer.Option(
        False, "--table", "-t", help="Display result in a table format"
    ),
    file: typer.FileText = typer.Option(
        None,
        "--file",
        "-f",
        help="JSON file containing Pathlookup output",
    ),
):
    """
    Analyze a path using Pathlookup and display the results.

    Parameters:
    verbose (bool): Whether to enable verbose mode or not.
    src_ip (str): The source IP address or subnet.
    dst_ip (str): The destination IP address or subnet.
    protocol (ProtocolChoices): The IP protocol to use (e.g. "tcp", "udp", "icmp").
    dst_port (str): The destination port number (only used with TCP/UDP protocols).
    src_port (str): The source port number (only used with TCP/UDP protocols).
    ttl (int): The time-to-live (TTL) value.
    fragment_offset (int): The fragment offset value.
    source_vrf (str): The source VRF (optional).
    secured_path (bool): Whether to use a secured path or not.
    l2_exclusion (bool): Remove L2 and FabricPath information.
    auto_pivot (bool): retry via the reverse path when the source has no default gateway
    pivot (str): to use to perform two PathLookup, first to identify where the source is connected
    table (bool): display the output as a table
    file (FileText): The JSON file containing Pathlookup output (optional).

    Returns:
    None
    """
    # if we use ICMP, we don't need tcp/udp ports
    if protocol == "icmp":
        src_port = 0
        dst_port = 0
    secured_path_msg = "Security: Stop" if secured_path else "Security: Continue"
    summary_path_msg = f"[bold]Pathlookup Analysis[/bold]\n[red]{src_ip}[/red]"
    summary_path_msg += f":[blue]{src_port}[/blue]" if src_port != 0 else ""
    summary_path_msg += f" --> [red]{dst_ip}[/red]"
    summary_path_msg += f":[blue]{dst_port}[/blue]" if dst_port != 0 else ""
    summary_path_msg += f" | {protocol} | {secured_path_msg}"
    summary_path_msg += f" | Source VRF: {source_vrf}" if source_vrf else ""
    print(summary_path_msg)
    if verbose:
        print(f"[italic]Debug: ttl:{ttl}, fragment offset:{fragment_offset}\n")
    if pivot:
        summary_path_msg += f" | Pivot: `{pivot}`"
        print(
            f"Using pivot IP `{pivot}` to find where the source IP `{src_ip}` is connected\n"
        )

    if not file:
        ipf_client = _client()
        result = get_pathlookup_model(
            ipf_client=ipf_client,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            ttl=ttl,
            source_vrf=source_vrf,
            fragment_offset=fragment_offset,
            secured_path=secured_path,
            pivot=pivot,
            auto_pivot=auto_pivot,
        )
        zonefw_interfaces = get_zonefw_interfaces(ipf_client)
    else:
        # Using json file to generate the output
        result = PathLookupResult(**json.load(file))
        zonefw_interfaces = None

    # Summary
    print("\n[bold] 1. Event Summary[/bold]")
    # Go through the topics and extract the information
    pathlookup_result = result.pathlookup.model_dump(by_alias=True)
    display_summary_topics(pathlookup_result)
    display_summary_global(pathlookup_result)

    # The pivot lookup already ran inside get_pathlookup_model(), so an empty
    # result here means no path regardless of how the entry point was chosen.
    if not result.edges:
        print("\n EXIT -> no Path available")
        sys.exit(0)

    if verbose:
        print("\n[bold] x. Path Edges[/bold] (explore all nextEdgeId)")
        display_all_edges(result.edges)

    path = enrich(result, zonefw_interfaces)
    if l2_exclusion:
        path = collapse_l2(path)

    print("\n[bold] 2. Path[/bold] (all branches)")
    if table_display:
        display_table(path, Table(title=summary_path_msg))
    else:
        show(path)

    print("\n[bold] 3. Security verdict[/bold]")
    show_blocked(result, zonefw_interfaces)


WRITE_FIELDS = [
    "create_status",
    "exists",
    "check_id",
    "job_id",
    "expectedPassingTraffic",
]


def _create_one(ipf_client, row, out_row, force_create):
    """Push one row into the Path Verifications table. Fills out_row in place and
    returns a short status line for the console."""
    payload = build_check_payload(row)
    if payload is None:
        out_row["create_status"] = "SKIPPED"
        return "SKIPPED (no expected intent)"

    out_row["expectedPassingTraffic"] = payload["expectedPassingTraffic"]
    exists = bool(check_exists(ipf_client, payload).get("exists"))
    out_row["exists"] = str(exists).lower()
    if exists and not force_create:
        out_row["create_status"] = "SKIPPED"
        return "SKIPPED existing"

    created = create_check(ipf_client, payload)
    out_row["create_status"] = "CREATED"
    out_row["check_id"] = created.get("id", "")
    out_row["job_id"] = created.get("jobId", "")
    return f"CREATED id={out_row['check_id']} job={out_row['job_id']}"


@app.command()
def bulk(
    input_file: Path = typer.Option(
        ..., "--input", "-i", exists=True, help="Input CSV of flows"
    ),
    output_file: Path = typer.Option(
        "results.csv", "--output", "-o", help="Output CSV path"
    ),
    snapshot: str = typer.Option(
        "", "--snapshot", help="Snapshot ID (default: the one from .env / $last)"
    ),
    delay: float = typer.Option(0.2, "--delay", help="Seconds between API calls"),
    limit: int = typer.Option(0, "--limit", help="Only process the first N rows"),
    create_path_verifications: bool = typer.Option(
        False,
        "--create-path-verifications",
        help="Also CREATE each flow as a saved path verification in IP Fabric",
    ),
    force_create: bool = typer.Option(
        False,
        "--force-create",
        help="Create even when an identical verification already exists",
    ),
    auto_pivot: bool = typer.Option(
        False,
        "--auto-pivot",
        help="On DEFAULT_GW_NOT_FOUND, reverse src/dst to find the source's entry point and retry (single-IP sources only)",
    ),
):
    """Run every flow in a CSV, and optionally save them as path verifications.

    Input columns: srcIP and dstIP required; srcPort, dstPort, protocol,
    application, security, expected and comment optional. Any other column is
    copied through to the output untouched.
    """
    if force_create and not create_path_verifications:
        raise typer.BadParameter(
            "--force-create only applies with --create-path-verifications"
        )

    with open(input_file, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if limit > 0:
        rows = rows[:limit]
    if not rows:
        print(f"[yellow]No rows in {input_file}[/yellow]")
        raise typer.Exit(1)

    ipf_client = _client(snapshot)
    # Once, not per row — it is the same table for every flow.
    zonefw_interfaces = get_zonefw_interfaces(ipf_client)

    has_expected = "expected" in rows[0]
    fields = list(rows[0].keys())
    for field in ["status", "verdict", "blocked_at", "rule", "branches", "details", "auto_pivot"]:
        if field == "verdict" and not has_expected:
            continue
        if field == "auto_pivot" and not auto_pivot:
            continue
        if field not in fields:
            fields.append(field)
    if create_path_verifications:
        fields.extend(f for f in WRITE_FIELDS if f not in fields)
        creatable = sum(
            1 for r in rows if normalise_expected(r.get("expected")) in
            ("allow", "block", "part")
        )
        print(
            f"[yellow]⚠ will CREATE path verifications in {ipf_client.base_url} "
            f"({len(rows)} rows, {creatable} with a usable intent)[/yellow]"
        )

    results = []
    for index, row in enumerate(rows, start=1):
        out_row = dict(row)
        label = f"{row.get('srcIP', '?')} → {row.get('dstIP', '?')}"
        print(f"[{index}/{len(rows)}] {label} ...", end=" ")

        pivoted = ""
        try:
            if auto_pivot:
                result, pivoted = model_row_auto_pivot(ipf_client, row)
                out_row["auto_pivot"] = pivoted
            else:
                result = ipf_client.diagram.model(unicast_from_row(row))
            outcome = classify(result, zonefw_interfaces)
        except Exception as error:
            outcome = {
                "status": "ERROR",
                "details": str(error),
                "blocked_at": "",
                "rule": "",
                "branches": 0,
            }
        out_row.update(outcome)

        verdict = ""
        if has_expected:
            verdict = evaluate_expectation(row.get("expected"), outcome["status"])
            out_row["verdict"] = verdict

        write_note = ""
        if create_path_verifications:
            for field in WRITE_FIELDS:
                out_row.setdefault(field, "")
            if outcome["status"] == "ERROR":
                out_row["create_status"] = "SKIPPED"
                write_note = "  SKIPPED (row failed)"
            else:
                try:
                    write_note = "  " + _create_one(
                        ipf_client, row, out_row, force_create
                    )
                except Exception as error:
                    out_row["create_status"] = "ERROR"
                    write_note = f"  CREATE ERROR {error}"

        results.append(out_row)
        marker = STATUS_MARKER.get(outcome["status"], "?")
        tag = f"[{verdict}] " if verdict else ""
        detail = outcome["details"]
        # escape(): details are full of '[zone-deny]' / '[fw]', which rich would
        # swallow as style markup — the CSV kept them, the console silently did not.
        print(
            escape(
                f"{marker} {outcome['status']:<8} {tag}"
                f"{detail[:90]}{'…' if len(detail) > 90 else ''}{write_note}"
                f"{f'  [auto-pivot {pivoted}]' if pivoted else ''}"
            )
        )
        if index < len(rows):
            time.sleep(delay)

    with open(output_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    counts = Counter(r["status"] for r in results)
    summary = "  ".join(f"{s}: {counts[s]}" for s in STATUSES if counts.get(s))
    line = f"\n→ {output_file}   {summary or 'no results'}"
    if has_expected:
        seen = Counter(r.get("verdict", "") for r in results)
        checks = "  ".join(
            f"{v}: {seen[v]}"
            for v in ("MATCH", "MISMATCH", "ASSESS", "?", "n/a")
            if seen.get(v)
        )
        line += f"   |  checks → {checks}" if checks else ""
    if create_path_verifications:
        made = Counter(r.get("create_status", "") for r in results)
        line += "   |  verifications → " + "  ".join(
            f"{k}: {v}" for k, v in made.items() if k
        )
    print(line)


if __name__ == "__main__":
    app()
