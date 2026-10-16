"""
# pathLookup.py
Talking to IP Fabric: build the client, run the path lookup, and print the parts
of the result that are not per-hop (the events summary, the raw edge dump).

Per-hop walking and enrichment live in `pathgraph.py`, which works on the SDK's
typed result rather than the raw JSON.
"""

import ipaddress

from ipfabric import IPFClient
from ipfabric.diagrams import Algorithm, OtherOptions, Unicast
from rich import print
from rich.markup import escape
from rich.table import Table

from .pathgraph import flat_rows
from .pivot import return_entry_point_pivot
from .utilis import SEVERITY_TEXT, display_severity
from .verdict import classify, expected_passing_traffic

GREEN = "0"
BLUE = "10"
AMBER = "20"
RED = "30"
COLOUR_DICT = {"Green": GREEN, "Blue": BLUE, "Amber": AMBER, "Red": RED}

# CSV defaults, carried over from the bulk scripts this module absorbed.
DEFAULT_SRC_PORT = "1024-65535"
DEFAULT_DST_PORT = "443"
DEFAULT_PROTOCOL = "tcp"
DEFAULT_SECURITY = "drop"
# Largest subnet accepted as an endpoint. Anything broader is almost always a typo,
# and IP Fabric will happily spend a long time simulating it before you find out.
MIN_PREFIX_LEN = 16


def create_ipf_client(
    base_url: str, auth: str, snapshot_id: str, verify: str, timeout: int
):
    """
    Creates an IPF client with the given base URL, authentication, IPF verification, and snapshot ID.
    """
    return IPFClient(
        base_url=base_url,
        auth=auth,
        snapshot_id=snapshot_id,
        verify=verify,
        timeout=timeout,
    )


def get_zonefw_interfaces(ipf_client: IPFClient):
    """
    Get from IP Fabric the tables containing the ZoneFW per Interfaces
    """
    return ipf_client.technology.security.zone_firewall_interfaces.all()


def validate_endpoint(value: str, field: str) -> None:
    """Reject anything that is not a single IP or a subnet of /MIN_PREFIX_LEN or
    narrower. Raises ValueError; typer callers wrap it in BadParameter."""
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen < MIN_PREFIX_LEN:
                raise ValueError(
                    f"{field} subnet {value} is larger than /{MIN_PREFIX_LEN} "
                    f"(got /{net.prefixlen}) — narrow it to /{MIN_PREFIX_LEN} or smaller"
                )
        else:
            ipaddress.ip_address(value)
    except ValueError as error:
        # Re-raise our own message as-is, wrap the stdlib parse errors.
        raise ValueError(
            str(error)
            if field in str(error)
            else f"{field} is not a valid IP/subnet: {value!r}"
        ) from error


def build_unicast(
    src_ip: str,
    dst_ip: str,
    protocol: str = DEFAULT_PROTOCOL,
    src_port: str = DEFAULT_SRC_PORT,
    dst_port: str = DEFAULT_DST_PORT,
    ttl: int = 128,
    fragment_offset: int = 0,
    secured_path: bool = True,
    application: str = None,
    first_hop_algorithm=None,
    icmp_application: bool = False,
) -> Unicast:
    """The single place a `Unicast` is constructed — CLI, bulk run and path
    verification create all go through here, so they cannot drift apart.

    L4 ports are omitted for ICMP. That is presentation only: the SDK's
    `l4_options` emits `{type, code}` for ICMP and ignores srcPorts/dstPorts, so
    the wire payload is identical either way.

    `icmp_application` exists because the two scripts merged here disagreed: the
    create path tagged portless ICMP with `applications="(icmp|ping)"`, the lookup
    path did not. Unlike the ports above, `otherOptions` IS serialised regardless of
    protocol, so unifying this silently would change live results."""
    kwargs = {
        "startingPoint": src_ip,
        "destinationPoint": dst_ip,
        "protocol": protocol,
        "ttl": ttl,
        "fragmentOffset": fragment_offset,
        "securedPath": secured_path,
    }
    if first_hop_algorithm:
        kwargs["firstHopAlgorithm"] = first_hop_algorithm
    if protocol != "icmp":
        kwargs["srcPorts"] = src_port
        kwargs["dstPorts"] = dst_port
    if application:
        kwargs["otherOptions"] = OtherOptions(applications=application)
    elif protocol == "icmp" and icmp_application:
        kwargs["otherOptions"] = OtherOptions(applications="(icmp|ping)")
    return Unicast(**kwargs)


def unicast_from_row(
    row: dict, icmp_application: bool = False, first_hop_algorithm=None
) -> Unicast:
    """One CSV row -> a validated `Unicast`.

    Only srcIP and dstIP are required; everything else falls back to the DEFAULT_*
    above. Raises ValueError on a bad row, which the caller turns into an ERROR
    result rather than aborting the whole file."""
    src = (row.get("srcIP") or "").strip()
    dst = (row.get("dstIP") or "").strip()
    protocol = (row.get("protocol") or DEFAULT_PROTOCOL).strip().lower()
    security = (row.get("security") or DEFAULT_SECURITY).strip().lower()

    if not src or not dst:
        raise ValueError("srcIP and dstIP are required")
    if protocol not in ("tcp", "udp", "icmp"):
        raise ValueError(f"protocol must be tcp/udp/icmp, got: {protocol!r}")
    validate_endpoint(src, "srcIP")
    validate_endpoint(dst, "dstIP")

    return build_unicast(
        src_ip=src,
        dst_ip=dst,
        protocol=protocol,
        src_port=(row.get("srcPort") or DEFAULT_SRC_PORT).strip(),
        dst_port=(row.get("dstPort") or DEFAULT_DST_PORT).strip(),
        # 'continue' simulates past a deny; anything else stops at it.
        secured_path=(security != "continue"),
        application=(row.get("application") or "").strip() or None,
        icmp_application=icmp_application,
        first_hop_algorithm=first_hop_algorithm,
    )


def model_row_auto_pivot(ipf_client: IPFClient, row: dict):
    """Lookup for one CSV row, with auto-pivot on DEFAULT_GW_NOT_FOUND.

    Returns (result, note): note is "host@iface" if the row was re-run pinned to that
    entry point, "no transit on reverse path: ..." if the pivot failed, else "". Quiet, so it can run inside the bulk progress line.
    Subnet sources are never pivoted (the events name a single IP)."""
    result = ipf_client.diagram.model(unicast_from_row(row))
    src = row["srcIP"].strip()
    if "/" in src or not _no_default_gw(result, src):
        return result, ""
    reverse = {**row, "srcIP": row["dstIP"], "dstIP": src, "security": "continue"}
    back = ipf_client.diagram.model(unicast_from_row(reverse))
    entry = return_entry_point_pivot(back)
    if not entry:
        return result, f"no transit on reverse path: {_why_no_transit(back)}"
    algo = Algorithm(entryPoints=[entry])
    result = ipf_client.diagram.model(unicast_from_row(row, first_hop_algorithm=algo))
    return result, f"{entry['hostname']}@{entry['iface']}"


# ── Path verifications: the only writes to IP Fabric in this repo ─────────────
def build_check_payload(row: dict) -> dict:
    """Saved-verification body for one CSV row, or None if the row states no
    creatable intent (see verdict.expected_passing_traffic)."""
    passing = expected_passing_traffic(row.get("expected"))
    if passing is None:
        return None
    unicast = unicast_from_row(row, icmp_application=True)
    return {
        "expectedPassingTraffic": passing,
        "parameters": unicast.model_dump(by_alias=True, exclude_none=True),
    }


def _json_or_empty(response):
    try:
        return response.json()
    except Exception:
        return {}


def _post(client: IPFClient, endpoint: str, body: dict) -> dict:
    """POST and raise on an error status. Never swallow a failure here: a silently
    half-populated Path Verifications table is worse than a loud row failure."""
    response = client.post(endpoint, json=body)
    data = _json_or_empty(response)
    if response.status_code >= 400:
        raise RuntimeError(data.get("message") or response.text)
    return data


def check_exists(client: IPFClient, payload: dict) -> dict:
    """Has an identical verification already been saved? Checked before every
    create so a rerun is a no-op rather than a duplicate flood."""
    return _post(
        client,
        "graphs/path-lookup/checks/exists",
        {"parameters": payload["parameters"]},
    )


def create_check(client: IPFClient, payload: dict) -> dict:
    """Create the saved path verification. Returns {id, jobId}."""
    return _post(client, "graphs/path-lookup/checks", payload)


def get_pathlookup_model(
    ipf_client: IPFClient,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: str,
    dst_port: str,
    ttl: str,
    fragment_offset: str,
    secured_path: bool,
    pivot: str = None,
    auto_pivot: bool = False,
    source_vrf: str = None,
    ipf_diagram: object = None,
):
    """
    Call IP Fabric with the given parameters and return the typed PathLookupResult.

    Parameters:
    src_ip (str): The source IP address.
    dst_ip (str): The destination IP address.
    protocol (str): The IP protocol to use (e.g. "tcp", "udp").
    src_port (str): The source port number.
    dst_port (str): The destination port number.
    ttl (str): The time-to-live (TTL) value.
    fragment_offset (str): The fragment offset value.
    secured_path (bool): Whether to use a secured path or not.
    pivot (str): Optional IP used to first locate where src_ip is connected.
    auto_pivot (bool): On DEFAULT_GW_NOT_FOUND, pivot through dst_ip (reverse path).

    Returns:
    PathLookupResult: the model returned by the SDK (res.nodes / res.edges /
    res.pathlookup), consumed by pathgraph.enrich().
    """
    # Initialize an diagram JSON object with the given parameters
    firstHopAlgorithm = (
        {"type": "automatic", "vrf": source_vrf}
        if source_vrf
        else {"type": "automatic"}
    )
    if not ipf_diagram:
        ipf_diagram = ipf_client.diagram
    lookup = dict(
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        ttl=ttl,
        fragment_offset=fragment_offset,
    )
    if pivot:
        firstHopAlgorithm = _pivot_algorithm(
            ipf_client, ipf_diagram, pivot, src_ip, firstHopAlgorithm, lookup
        )

    uni = build_unicast(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        ttl=ttl,
        fragment_offset=fragment_offset,
        secured_path=secured_path,
        first_hop_algorithm=firstHopAlgorithm,
    )

    # Call IP Fabric and retrieve the path lookup result
    result = ipf_diagram.model(uni)

    # Auto-pivot: the source has no gateway, so locate it via the reverse path
    if auto_pivot and not pivot and _no_default_gw(result, src_ip):
        print(
            f"[blue][italic][bold]Info: [/bold][/blue][/italic]DEFAULT_GW_NOT_FOUND for `{src_ip}`, auto-pivot: using `{dst_ip}` to find where it is connected"
        )
        algo = _pivot_algorithm(
            ipf_client, ipf_diagram, dst_ip, src_ip, firstHopAlgorithm, lookup
        )
        if algo is not firstHopAlgorithm:
            uni = build_unicast(
                src_ip=src_ip,
                dst_ip=dst_ip,
                secured_path=secured_path,
                first_hop_algorithm=algo,
                **lookup,
            )
            result = ipf_diagram.model(uni)
    return result


def _no_default_gw(result, src_ip: str) -> bool:
    """True if the global events report DEFAULT_GW_NOT_FOUND for src_ip."""
    events = result.pathlookup.model_dump(by_alias=True)["eventsSummary"]["global"]
    return any(
        e["name"] == "DEFAULT_GW_NOT_FOUND" and any(src_ip in d for d in e["details"])
        for e in events
    )


def _pivot_algorithm(ipf_client, ipf_diagram, pivot, src_ip, default, lookup):
    """
    Look up pivot -> src_ip and return an entry-point Algorithm for the leaving
    device, or `default` (with a warning) if that path has no transit.
    """
    pivot_result = get_pathlookup_model(
        ipf_client=ipf_client,
        ipf_diagram=ipf_diagram,
        src_ip=pivot,
        dst_ip=src_ip,
        secured_path=False,
        **lookup,
    )
    if entry_point := return_entry_point_pivot(pivot_result):
        print(
            f"[blue][italic][bold]Info: [/bold][/blue][/italic]Entry point for the source `{src_ip} is: `{entry_point['hostname']}@{entry_point['iface']}`"
        )
        return Algorithm(entryPoints=[entry_point])
    print(
        f"[yellow][italic][bold]Warning: [/bold][/yellow][/italic]Pivot `{pivot}` will not be used. From the pivot to the source `({src_ip})` there is no transit: {escape(_why_no_transit(pivot_result))}"
    )
    return default


def _why_no_transit(res) -> str:
    """Where the reverse (pivot -> src) path stopped, e.g. 'sw01 [switch]: Route ... not found'."""
    out = classify(res)
    return ": ".join(filter(None, (out["blocked_at"], out["rule"]))) or out["details"]


def display_summary_topics(pathlookup_result: dict):
    """
    Display summary information, highlighting issues with NAT, ACL, etc.

    Parameters:
    pathlookup_result (dict): res.pathlookup.model_dump(by_alias=True)

    Returns:
    None
    """
    # Initialize a dictionary to store the summary information for each topic
    topics_results = {}

    # Print the Summary header
    print("[bold]  - Summary[/bold]")

    # Iterate over each topic in the eventsSummary dictionary
    for topic, topic_data in pathlookup_result["eventsSummary"]["topics"].items():
        if not topic_data:
            continue
        topics_results[topic] = []

        # Iterate over each color in the COLOUR_DICT dictionary
        for colour, colour_key in COLOUR_DICT.items():
            value = topic_data.get(colour_key, 0)
            # If the color value is not zero, add it to the list of results for this topic
            if value != 0:
                topics_results[topic].append(f"      - {colour}: {value}")

    # Display the summary information for each topic
    if not any(topics_results.values()):
        print("No summary information for this path")
    else:
        for topic, topic_results in topics_results.items():
            if topic_results:
                print(f"    - {topic}")
                print("\n".join(f"{result}" for result in topic_results))


def display_summary_global(pathlookup_result: dict):
    """
    Display information related to the Global key.

    Parameters:
    pathlookup_result (dict): res.pathlookup.model_dump(by_alias=True)

    Returns:
    None
    """
    # Check if there is any Global information to display
    if len(pathlookup_result["eventsSummary"]["global"]) > 0:
        global_info = pathlookup_result["eventsSummary"]["global"]

        # Print the Global information header
        print("[bold]  - Global[/bold]")

        # Print each piece of Global information
        for info in global_info:
            message = [info["name"]]
            message.extend(info["details"])
            message.append(str(info["severity"]))
            message = " | ".join(message)
            print(f"{message}")


def display_all_edges(pathlookup_edges: dict):
    """
    Display all edges in the path, highlighting when multiple egress points exist.
    Debug view (--verbose): the enriched tree from pathgraph.show() is the real
    output, this is the unfiltered adjacency it was built from.

    Parameters:
    pathlookup_edges (dict): res.edges

    Returns:
    list: A list of all edges involved in the path.
    """
    # Collect all next edge IDs in a list
    next_edge_ids = [next(iter(pathlookup_edges.values())).id]
    for edge in pathlookup_edges.values():
        if len(edge.nextEdgeIds) > 1:
            next_edge_ids.extend(
                f"{path}--multiple-egress" for path in edge.nextEdgeIds
            )
        elif len(edge.nextEdgeIds) == 1:
            next_edge_ids.append(edge.nextEdgeIds[0])

    # Process each edge ID to extract the relevant information
    processed_edges = []
    for edge in next_edge_ids:
        processed_edge = edge.split("--")
        processed_edge = [
            (
                f"{e.split('!')[1]}"
                if "!" in e
                else f"{e.split('@')[1]}"
                if "@" in e
                else e
            )
            for e in processed_edge
        ]
        processed_edges.append("--".join(processed_edge))

    # Print the list of edges, highlighting multiple egress points
    final_all_edges = []
    prev_device_src = ""
    for edge in processed_edges:
        if edge not in final_all_edges:
            final_all_edges.append(edge)
            device_src = edge.split("@")[0] if edge.split("@") else ""
            if device_src == prev_device_src:
                (
                    print("".join([" └ ", edge]))
                    if "multiple-egress" in edge
                    else print(edge)
                )
            else:
                print(edge)
            prev_device_src = device_src

    return final_all_edges


def display_table(structure, output_table: Table):
    """
    Render the enriched path as a flat table. Forks are flattened, with a Branch
    column marking which leg (↳1, ↳2, …) each hop belongs to so ECMP is not lost.

    Parameters:
    structure: pathgraph.enrich() output
    output_table (Table): the rich Table to populate

    Returns:
    None
    """
    for column, style in (
        ("Br", "dim"),
        ("Ingress", None),
        ("Device", "cyan"),
        ("Egress", None),
        ("Protocol", "green"),
        ("VRF", None),
        ("Sec", None),
        ("Rule Chain", None),
        ("ZoneFW", None),
    ):
        output_table.add_column(column, style=style, no_wrap=(column == "Device"))

    for branch, hop in flat_rows(structure):
        security = rule_chain = ""
        if hop["blocked"]:
            security, rule_chain = SEVERITY_TEXT[30], hop["drop_reason"] or ""
        if hop["security"]:
            top = hop["security"][0]
            security = display_severity(top["severity"], text=True)
            rule_chain = top["policy"] or ""
        vrf = hop["vrf"] if isinstance(hop["vrf"], str) else ",".join(hop["vrf"] or [])
        output_table.add_row(
            branch,
            ",".join(hop["ingress"] or ["-"]),
            hop["device"],
            ",".join(hop["egress"] or ["-"]),
            hop["protocol"],
            vrf,
            security,
            rule_chain,
            hop["zonefw"] or "",
        )
    print(output_table)
