"""
# lookup.py
Everything needed to turn a flow into a typed path lookup result: the IP Fabric
client, the one `Unicast` builder, CSV-row parsing, and the lookup itself with its
two optional pivots (manual `--pivot IP`, or `--auto-pivot` on DEFAULT_GW_NOT_FOUND).

A *flow* is the dict of `build_unicast()` keyword arguments. `flow_from_row()`
makes one from a CSV row; the `single` command makes one from its options. Both
then go through `run_lookup()`, so the pivot logic exists once.

Printing lives in `display.py`, saved verifications in `checks.py`.
"""

import ipaddress
from typing import NamedTuple

from ipfabric import IPFClient
from ipfabric.diagrams import Algorithm, OtherOptions, Unicast
from ipfabric.diagrams.output_models import PathLookupResult

from .pivot import return_entry_point_pivot
from .verdict import classify

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


def flow_from_row(row: dict, icmp_application: bool = False) -> dict:
    """One CSV row -> a validated flow (`build_unicast()` keyword arguments).

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

    return {
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "src_port": (row.get("srcPort") or DEFAULT_SRC_PORT).strip(),
        "dst_port": (row.get("dstPort") or DEFAULT_DST_PORT).strip(),
        # 'continue' simulates past a deny; anything else stops at it.
        "secured_path": security != "continue",
        "application": (row.get("application") or "").strip() or None,
        "icmp_application": icmp_application,
    }


def unicast_from_row(row: dict, icmp_application: bool = False) -> Unicast:
    """One CSV row -> a validated `Unicast` (no pivot)."""
    return build_unicast(**flow_from_row(row, icmp_application))


# ── The lookup, with its optional pivots ──────────────────────────────────────
class PivotInfo(NamedTuple):
    """What a pivot found. `entry` is {"sn", "iface", "hostname"}, or None when the
    reverse path never left the fabric (then `why_not` says where it stopped)."""

    via: str
    entry: dict | None
    why_not: str
    auto: bool


class Lookup(NamedTuple):
    """`unicast` is what produced `result` (pinned to the entry point if a pivot
    worked) and `raw` is that response's JSON, kept so it can be saved as-is.
    `pivot` is None when no pivot was attempted."""

    result: PathLookupResult
    unicast: Unicast
    raw: dict
    pivot: PivotInfo | None


def run_lookup(
    diagram, flow: dict, pivot: str = None, auto_pivot: bool = False
) -> Lookup:
    """Run `flow`, optionally pinned to where the source is attached.

    - `pivot`: look up pivot -> src first and pin the real lookup to the device
      where that path leaves to the transit.
    - `auto_pivot`: same, but only when the plain lookup reports DEFAULT_GW_NOT_FOUND
      for the source, and using the flow's own destination as the pivot. Ignored
      for subnet sources (the event names a single IP) or when `pivot` is given.

    A pivot that finds no entry point is reported in `Lookup.pivot` and the plain
    result is kept."""
    info = _find_entry(diagram, flow, pivot, auto=False) if pivot else None
    unicast = _pinned(flow, info)
    result, raw = _fetch(diagram, unicast)

    src = flow["src_ip"]
    if auto_pivot and not pivot and "/" not in src and _no_default_gw(result, src):
        info = _find_entry(diagram, flow, flow["dst_ip"], auto=True)
        if info.entry:
            unicast = _pinned(flow, info)
            result, raw = _fetch(diagram, unicast)
    return Lookup(result, unicast, raw, info)


def rerun_unsecured(diagram, lookup: Lookup) -> Lookup:
    """The same lookup, same entry point, but continuing past denies. Used to show what
    lies beyond a deny; it cannot tell whether the traffic works (see `run_lookup`
    with a secured flow for that)."""
    unicast = lookup.unicast.model_copy(update={"securedPath": False})
    result, raw = _fetch(diagram, unicast)
    return Lookup(result, unicast, raw, lookup.pivot)


def _fetch(diagram, unicast: Unicast):
    """One API call: the raw JSON and the typed model parsed from it. (The SDK's own
    `diagram.model()` also links nodes into edges, which pathgraph does not need —
    it reads either form — and it throws the JSON away.)"""
    raw = diagram.json(unicast)
    return PathLookupResult(**raw), raw


def _find_entry(diagram, flow: dict, via: str, auto: bool) -> PivotInfo:
    """Look up via -> src and return the device where that path leaves the fabric."""
    reverse = {
        **flow,
        "src_ip": via,
        "dst_ip": flow["src_ip"],
        "secured_path": False,
        "first_hop_algorithm": None,
    }
    back, _ = _fetch(diagram, build_unicast(**reverse))
    entry = return_entry_point_pivot(back)
    return PivotInfo(via, entry, "" if entry else _why_no_transit(back), auto)


def _pinned(flow: dict, info: PivotInfo | None) -> Unicast:
    """The flow's Unicast, with the pivot's entry point as first hop if it has one."""
    if info and info.entry:
        flow = {**flow, "first_hop_algorithm": Algorithm(entryPoints=[info.entry])}
    return build_unicast(**flow)


def _no_default_gw(result, src_ip: str) -> bool:
    """True if the global events report DEFAULT_GW_NOT_FOUND for src_ip."""
    events = result.pathlookup.model_dump(by_alias=True)["eventsSummary"]["global"]
    return any(
        e["name"] == "DEFAULT_GW_NOT_FOUND" and any(src_ip in d for d in e["details"])
        for e in events
    )


def _why_no_transit(res) -> str:
    """Where the reverse path stopped, e.g. 'sw01 [switch]: Route ... not found'."""
    out = classify(res)
    return ": ".join(filter(None, (out["blocked_at"], out["rule"]))) or out["details"]


def pivot_note(info: PivotInfo | None) -> str:
    """One-line pivot outcome for the bulk console line and CSV column."""
    if info is None:
        return ""
    if info.entry:
        return f"{info.entry['hostname']}@{info.entry['iface']}"
    return f"no transit on reverse path: {info.why_not}"
