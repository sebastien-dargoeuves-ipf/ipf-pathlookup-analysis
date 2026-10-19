"""
# dataset.py
Build a `bulk` input CSV from IP Fabric's host inventory: one representative host per
subnet, then every source -> destination pair between them. The output has the same
header as any hand-written input file, so it can be edited before running.

Pure functions over plain data (no API, no CLI); the `dataset` command feeds them.
"""

import csv
import ipaddress
from itertools import combinations, permutations
from pathlib import Path

# Same columns as flows_sample.csv. Left empty: the defaults in lookup.py apply
# (source port 1024-65535, security 'drop'), and an empty `expected` just means
# "no stated intent" for the verdict and create steps.
FIELDS = [
    "srcIP",
    "dstIP",
    "srcPort",
    "dstPort",
    "protocol",
    "application",
    "security",
    "comment",
    "expected",
]


def host_ips(hosts, vrfs=None) -> list[str]:
    """Unique IPv4 addresses of the inventory hosts, in address order. `vrfs` keeps
    only hosts in those VRFs. IPv6 and unparsable entries are skipped."""
    ips = set()
    for host in hosts:
        if vrfs and host.get("vrf") not in vrfs:
            continue
        try:
            ip = ipaddress.ip_address(host.get("ip") or "")
        except ValueError:
            continue
        if ip.version == 4:
            ips.add(ip)
    return [str(ip) for ip in sorted(ips)]


def one_per_subnet(ips: list[str], prefix: int) -> list[str]:
    """One IP per /`prefix` subnet: the lowest address, since `ips` is sorted.
    A `prefix` of 0 keeps every IP."""
    if not prefix:
        return ips
    representatives = {}
    for ip in ips:
        representatives.setdefault(
            ipaddress.ip_network(f"{ip}/{prefix}", strict=False), ip
        )
    return list(representatives.values())


def flows(
    ips: list[str], protocol: str, dst_port: str, bidirectional: bool
) -> list[dict]:
    """Every pair of `ips` as a CSV row: A -> B and B -> A, or only A -> B (in address
    order) when not bidirectional. ICMP rows carry no port."""
    pairs = permutations(ips, 2) if bidirectional else combinations(ips, 2)
    port = "" if protocol == "icmp" else dst_port
    return [
        {"srcIP": src, "dstIP": dst, "dstPort": port, "protocol": protocol}
        for src, dst in pairs
    ]


def write_dataset(path: Path, rows: list[dict]) -> None:
    """Write the rows with the standard header, creating the folder if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, restval="")
        writer.writeheader()
        writer.writerows(rows)
