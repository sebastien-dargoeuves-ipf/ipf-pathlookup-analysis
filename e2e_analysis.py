"""
# Pathlookup analysis

Two ways in:

- `single` — one flow, rendered as a tree (or a table) with the security verdict.
  Optionally pivoted through another IP to find where the source is attached.
- `bulk` — a CSV of flows, each simulated and scored against its stated intent.
  With `--create-path-verifications`, each row is also pushed into IP Fabric's Path
  Verifications table, which is the only thing in this repo that writes.
- `dataset` — build a `bulk` input CSV from IP Fabric's host inventory.
"""

import csv
import ipaddress
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from pathlib import Path

import typer
from dotenv import find_dotenv, load_dotenv
from ipfabric.diagrams.output_models import PathLookupResult
from rich import print

from modules.bulk import Run, output_fields, plan_names, process_row, result_line, summary_line
from modules.dataset import flows, host_ips, one_per_subnet, write_dataset
from modules.display import (
    display_all_edges,
    display_summary_global,
    display_summary_topics,
    display_table,
    show_pivot,
)
from modules.lookup import (
    create_ipf_client,
    get_zonefw_interfaces,
    pivot_note,
    run_lookup,
)
from modules.pathgraph import collapse_l2, enrich, show, show_blocked
from modules.report import fingerprint, flow_name, write_flow_report
from modules.rules import Rules
from modules.verdict import (
    classify,
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


def validate_ipv4_address(address: str):
    """
    Validate that a string is a valid IPv4 address or subnet; returns it unchanged.
    Raises BadParameter otherwise (an empty string included: src/dst are required).
    """
    try:
        ipaddress.IPv4Network(address)
    except ValueError as error:
        raise typer.BadParameter(error) from error
    return address


def validate_ipv4_address_or_empty(address: str):
    """Same, for an optional option: empty means not given."""
    return validate_ipv4_address(address) if address else None


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
    first_path: bool = typer.Option(
        False,
        "--first-path",
        "-fp",
        help="Follow one branch at each fork (the first that reaches the destination) in the path view",
    ),
    security_detail: bool = typer.Option(
        False,
        "--security-detail",
        help="Look up the rule behind each deny (ACL / zone firewall, ACI group names) in IP Fabric; extra calls",
    ),
    report_dir: Path = typer.Option(
        None,
        "--report-dir",
        help="Also write this flow's files here: JSON, markdown report and summary",
    ),
    png: bool = typer.Option(
        False, "--png", help="With --report-dir: also save the diagram as a PNG"
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
    first_path (bool): in the table, follow one branch at each fork
    security_detail (bool): look up the rule behind each deny
    report_dir (Path): write the flow's JSON / markdown (and PNG) files there
    file (FileText): The JSON file containing Pathlookup output (optional).

    Returns:
    None
    """
    if png and not report_dir:
        raise typer.BadParameter("--png only applies with --report-dir")
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
        print(
            f"Using pivot IP `{pivot}` to find where the source IP `{src_ip}` is connected\n"
        )

    if not file:
        ipf_client = _client()
        flow = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol.value,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl": ttl,
            "fragment_offset": fragment_offset,
            "secured_path": secured_path,
            "first_hop_algorithm": (
                {"type": "automatic", "vrf": source_vrf}
                if source_vrf
                else {"type": "automatic"}
            ),
        }
        lookup = run_lookup(
            ipf_client.diagram, flow, pivot=pivot, auto_pivot=auto_pivot
        )
        if lookup.pivot:
            show_pivot(lookup.pivot, src_ip)
        result = lookup.result
        zonefw_interfaces = get_zonefw_interfaces(ipf_client)
        rules = Rules(ipf_client) if security_detail else None
    else:
        # Using json file to generate the output
        result = PathLookupResult(**json.load(file))
        zonefw_interfaces = None
        rules = None
        lookup = None

    # Summary
    print("\n[bold] 1. Event Summary[/bold]")
    # Go through the topics and extract the information
    pathlookup_result = result.pathlookup.model_dump(by_alias=True)
    display_summary_topics(pathlookup_result)
    display_summary_global(pathlookup_result)

    # Any pivot already ran inside run_lookup(), so an empty
    # result here means no path regardless of how the entry point was chosen.
    if not result.edges:
        print("\n EXIT -> no Path available")
        _report_single(ipf_client, report_dir, flow, lookup, zonefw_interfaces, rules, png)
        sys.exit(0)

    if verbose:
        print("\n[bold] x. Path Edges[/bold] (explore all nextEdgeId)")
        display_all_edges(result.edges)

    path = enrich(result, zonefw_interfaces, rules)
    if l2_exclusion:
        path = collapse_l2(path)

    scope = "first path only" if first_path else "all branches"
    print(f"\n[bold] 2. Path[/bold] ({scope})")
    if table_display:
        display_table(path, first_path=first_path)
    else:
        show(path, first_path=first_path, details=verbose)

    print("\n[bold] 3. Security verdict[/bold]")
    show_blocked(result, zonefw_interfaces, rules)

    _report_single(ipf_client, report_dir, flow, lookup, zonefw_interfaces, rules, png)


def _report_single(ipf_client, report_dir, flow, lookup, zonefw_interfaces, rules, png):
    """`single --report-dir`: write the flow's files and say where. Does nothing
    without --report-dir, or when the result came from --file (no lookup to save)."""
    if not (report_dir and lookup):
        return
    png_bytes = ipf_client.diagram.png(lookup.unicast) if png else None
    auto = bool(lookup.pivot and lookup.pivot.auto)
    report = write_flow_report(
        report_dir,
        flow_name(flow, set()),
        flow,
        lookup,
        classify(lookup.result, zonefw_interfaces),
        zonefw_interfaces,
        {"Pivot": pivot_note(lookup.pivot)},
        png_bytes,
        fingerprint(flow, ipf_client.snapshot_id, auto, rules is not None),
        rules,
    )
    print(f"\n[bold] Report[/bold] -> {report_dir / report}")


@app.command()
def dataset(
    output_file: Path = typer.Option(
        "flows_dataset.csv", "--output", "-o", help="Output CSV path (input for `bulk`)"
    ),
    snapshot: str = typer.Option(
        "", "--snapshot", help="Snapshot ID (default: the one from .env / $last)"
    ),
    protocol: ProtocolChoices = typer.Option(
        ProtocolChoices.icmp, "--protocol", "-p", help="Protocol for every flow"
    ),
    dst_port: str = typer.Option(
        "443", "--dst-port", "-dp", help="Destination port (tcp/udp only)"
    ),
    vrf: list[str] = typer.Option(
        None, "--vrf", help="Only hosts in this VRF; repeat for several. Default: all VRFs"
    ),
    subnet_prefix: int = typer.Option(
        24,
        "--subnet-prefix",
        min=0,
        max=32,
        help="Keep one host (the lowest address) per subnet of this size; 0 keeps every host",
    ),
    bidirectional: bool = typer.Option(
        True, "--bidirectional/--no-bidirectional", help="A -> B and B -> A, or A -> B only"
    ),
):
    """Build a `bulk` input file from the host inventory: one host per subnet, then
    every source -> destination pair between them. Edit the file (ports, `expected`,
    `security`) before running it with `bulk`."""
    ipf_client = _client(snapshot)
    print(f"Reading hosts from {ipf_client.base_url} ...")
    ips = host_ips(ipf_client.inventory.hosts.all(), set(vrf or []))
    chosen = one_per_subnet(ips, subnet_prefix)
    if len(chosen) < 2:
        raise typer.BadParameter(
            f"need at least 2 hosts to build flows, found {len(chosen)} "
            f"({len(ips)} IPv4 hosts before the per-subnet filter)"
        )
    rows = flows(chosen, protocol.value, dst_port, bidirectional)
    write_dataset(output_file, rows)
    print(
        f"{len(ips)} hosts -> {len(chosen)} after one-per-/{subnet_prefix} "
        f"-> {len(rows)} flows written to {output_file}"
        if subnet_prefix
        else f"{len(ips)} hosts -> {len(rows)} flows written to {output_file}"
    )


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
    security_detail: bool = typer.Option(
        False,
        "--security-detail",
        help="Look up the rule behind each deny (ACL / zone firewall, ACI group names) in IP Fabric; extra calls",
    ),
    report_dir: Path = typer.Option(
        None,
        "--report-dir",
        help="Write each flow's files here: JSON, markdown report and summary",
    ),
    png: bool = typer.Option(
        False, "--png", help="With --report-dir: also save each diagram as a PNG"
    ),
    parallel: int = typer.Option(
        1, "--parallel", min=1, max=10, help="Run this many flows at once (--delay is then ignored)"
    ),
    resume: bool = typer.Option(
        False,
        "--resume",
        help="With --report-dir: reuse finished flows from an earlier run instead of looking them up again",
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
    if png and not report_dir:
        raise typer.BadParameter("--png only applies with --report-dir")
    if resume and not report_dir:
        raise typer.BadParameter("--resume only applies with --report-dir")
    if security_detail and not report_dir:
        raise typer.BadParameter("--security-detail only applies with --report-dir")

    rows = _read_rows(input_file, limit)
    ipf_client = _client(snapshot)
    # Once, not per row — it is the same table for every flow.
    zonefw_interfaces = get_zonefw_interfaces(ipf_client)
    rules = Rules(ipf_client) if security_detail else None

    has_expected = "expected" in rows[0]
    fields = output_fields(
        rows, has_expected, auto_pivot, create_path_verifications, report_dir
    )
    if create_path_verifications:
        _warn_creating(ipf_client, rows)

    run = Run(
        ipf_client, zonefw_interfaces, rules, auto_pivot, has_expected,
        create_path_verifications, force_create, report_dir, png, resume,
    )
    names = plan_names(rows) if report_dir else [None] * len(rows)
    results = _run_rows(run, rows, names, parallel, delay)

    _write_csv(output_file, fields, results)
    print(summary_line(output_file, results, has_expected, create_path_verifications))
    if report_dir:
        print(f"→ reports in {report_dir}/")


def _run_rows(run, rows, names, parallel, delay):
    """Process every row and return the CSV rows in input order.

    One at a time, the label is printed before the lookup so a slow flow is visible.
    In parallel, a row's line is printed when it finishes, so lines can be out of
    order (the `[i/n]` prefix says which row it is); the CSV is always in input order."""
    total = len(rows)
    labels = [
        f"[{i}/{total}] {row.get('srcIP', '?')} → {row.get('dstIP', '?')} ..."
        for i, row in enumerate(rows, start=1)
    ]
    results = [None] * total

    if parallel == 1:
        for i, (row, name) in enumerate(zip(rows, names)):
            print(labels[i], end=" ")
            res = process_row(run, row, name)
            results[i] = res.out_row
            print(result_line(res))
            if i < total - 1 and not res.resumed:
                time.sleep(delay)
        return results

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {
            pool.submit(process_row, run, row, name): i
            for i, (row, name) in enumerate(zip(rows, names))
        }
        for future in as_completed(futures):
            i = futures[future]
            res = future.result()
            results[i] = res.out_row
            print(f"{labels[i]} {result_line(res)}")
    return results


def _read_rows(input_file: Path, limit: int) -> list[dict]:
    """The CSV rows to run (first `limit` if set). Exits if there are none."""
    with open(input_file, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if limit > 0:
        rows = rows[:limit]
    if not rows:
        print(f"[yellow]No rows in {input_file}[/yellow]")
        raise typer.Exit(1)
    return rows


def _warn_creating(ipf_client, rows):
    """Say loudly, before anything runs, that this run writes to IP Fabric."""
    creatable = sum(
        1
        for r in rows
        if normalise_expected(r.get("expected")) in ("allow", "block", "part")
    )
    print(
        f"[yellow]⚠ will CREATE path verifications in {ipf_client.base_url} "
        f"({len(rows)} rows, {creatable} with a usable intent)[/yellow]"
    )


def _write_csv(output_file, fields, results):
    with open(output_file, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


if __name__ == "__main__":
    app()
