"""
Self-check for modules/report.py — run it with `python tests/test_report.py`.
No pytest, no server. The markdown content itself is covered by the golden snapshots
(`*-report.expected.txt`); this checks the file naming.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.lookup import flow_from_row
from modules.report import flow_name


def name_of(row, taken=None):
    return flow_name(flow_from_row(row), set() if taken is None else taken)


def main():
    # Subnet slash and port list/range become filename-safe; default src port is omitted.
    assert name_of({"srcIP": "10.0.0.1/24", "dstIP": "10.1.0.5", "dstPort": "443,3389"}) == (
        "10.0.0.1-24_to_10.1.0.5_tcp-443+3389"
    )
    # A non-default source port is part of the name; ICMP has no ports at all.
    assert name_of({"srcIP": "10.0.0.1", "dstIP": "10.1.0.5", "srcPort": "5000"}).endswith(
        "_tcp-443_sp5000"
    )
    assert name_of({"srcIP": "10.0.0.1", "dstIP": "10.1.0.5", "protocol": "icmp"}) == (
        "10.0.0.1_to_10.1.0.5_icmp"
    )
    # Two flows that differ only in something the name omits do not overwrite each other.
    taken = set()
    row = {"srcIP": "10.0.0.1", "dstIP": "10.1.0.5"}
    names = [name_of(row, taken) for _ in range(3)]
    assert names == ["10.0.0.1_to_10.1.0.5_tcp-443", "10.0.0.1_to_10.1.0.5_tcp-443_2",
                     "10.0.0.1_to_10.1.0.5_tcp-443_3"], names
    print("report self-check OK")


if __name__ == "__main__":
    main()
