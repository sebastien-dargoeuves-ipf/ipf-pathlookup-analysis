"""
Self-check for modules/dataset.py — run it with `python tests/test_dataset.py`.
No pytest, no server: the host inventory is a list of dicts.
"""

import csv
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.dataset import FIELDS, flows, host_ips, one_per_subnet, write_dataset
from modules.lookup import flow_from_row

HOSTS = [
    {"ip": "10.0.1.20", "vrf": "a"},
    {"ip": "10.0.1.5", "vrf": "a"},  # same /24 as .20, lower address
    {"ip": "10.0.2.9", "vrf": "b"},
    {"ip": "10.0.1.20", "vrf": "b"},  # duplicate IP in another VRF
    {"ip": "2001:db8::1", "vrf": "a"},  # IPv6: skipped
    {"ip": "", "vrf": "a"},  # no IP: skipped
    {"ip": "not-an-ip", "vrf": "a"},  # garbage: skipped
]


def main():
    ips = host_ips(HOSTS)
    assert ips == ["10.0.1.5", "10.0.1.20", "10.0.2.9"], ips  # numeric order, deduped
    assert host_ips(HOSTS, vrfs={"b"}) == ["10.0.1.20", "10.0.2.9"]

    # One per /24 keeps the lowest address; prefix 0 keeps everything.
    assert one_per_subnet(ips, 24) == ["10.0.1.5", "10.0.2.9"]
    assert one_per_subnet(ips, 0) == ips

    two_way = flows(["10.0.1.5", "10.0.2.9"], "tcp", "443", bidirectional=True)
    assert [(r["srcIP"], r["dstIP"]) for r in two_way] == [
        ("10.0.1.5", "10.0.2.9"),
        ("10.0.2.9", "10.0.1.5"),
    ]
    assert len(flows(ips, "tcp", "443", bidirectional=False)) == 3  # n*(n-1)/2
    assert len(flows(ips, "tcp", "443", bidirectional=True)) == 6  # n*(n-1)
    assert flows(["10.0.1.5", "10.0.2.9"], "icmp", "443", True)[0]["dstPort"] == ""

    # The file has the standard header and every row is a valid bulk input row.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sub" / "flows.csv"
        write_dataset(path, two_way)
        rows = list(csv.DictReader(open(path, newline="")))
    assert list(rows[0].keys()) == FIELDS
    for row in rows:
        flow_from_row(row)  # raises ValueError on a bad row
    print("dataset self-check OK")


if __name__ == "__main__":
    main()
