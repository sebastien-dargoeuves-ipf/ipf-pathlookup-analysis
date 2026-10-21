"""
Self-check for modules/report.py — run it with `python tests/test_report.py`.
No pytest, no server. The markdown content itself is covered by the golden snapshots
(`*-report.expected.txt`); this checks the file naming.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.lookup import flow_from_row
import json
import tempfile

from modules.report import fingerprint, flow_name, load_saved_flow


def name_of(row, taken=None):
    return flow_name(flow_from_row(row), set() if taken is None else taken)


def main():
    # Subnet slash and port list/range become filename-safe; default src port is omitted.
    assert name_of(
        {"srcIP": "10.0.0.1/24", "dstIP": "10.1.0.5", "dstPort": "443,3389"}
    ) == ("10.0.0.1-24_to_10.1.0.5_tcp-443+3389")
    # A non-default source port is part of the name; ICMP has no ports at all.
    assert name_of(
        {"srcIP": "10.0.0.1", "dstIP": "10.1.0.5", "srcPort": "5000"}
    ).endswith("_tcp-443_sp5000")
    assert name_of({"srcIP": "10.0.0.1", "dstIP": "10.1.0.5", "protocol": "icmp"}) == (
        "10.0.0.1_to_10.1.0.5_icmp"
    )
    # Two flows that differ only in something the name omits do not overwrite each other.
    taken = set()
    row = {"srcIP": "10.0.0.1", "dstIP": "10.1.0.5"}
    names = [name_of(row, taken) for _ in range(3)]
    assert names == [
        "10.0.0.1_to_10.1.0.5_tcp-443",
        "10.0.0.1_to_10.1.0.5_tcp-443_2",
        "10.0.0.1_to_10.1.0.5_tcp-443_3",
    ], names
    # `single` builds its flow without an application; the fingerprint must cope.
    single_flow = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.1.0.5",
        "protocol": "tcp",
        "src_port": "1024",
        "dst_port": "443",
        "secured_path": False,
    }
    assert '"application": null' in fingerprint(single_flow, "snap", False)
    # --resume reads the SAVED verdict. For `security: continue` the saved JSON is the
    # continuing path, which would score REACHED; the verdict came from a secured lookup.
    outcome = {
        "status": "BLOCKED",
        "details": "d",
        "blocked_at": "fw",
        "rule": "r",
        "branches": 1,
    }
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        (out / "f.json").write_text("{}")
        (out / "f.md").write_text(
            f"<!-- flow: FP -->\n<!-- outcome: {json.dumps(outcome)} -->\n\n"
            "| Pivot | HWLAB@e1 |\n"
        )
        assert load_saved_flow(out, "f", "FP", need_png=False) == (outcome, "HWLAB@e1")
        assert (
            load_saved_flow(out, "f", "OTHER", need_png=False) is None
        )  # other parameters
        assert (
            load_saved_flow(out, "f", "FP", need_png=True) is None
        )  # PNG wanted, absent
        assert load_saved_flow(out, "missing", "FP", need_png=False) is None
        (out / "f.md").write_text("<!-- flow: FP -->\n")  # no saved verdict
        assert load_saved_flow(out, "f", "FP", need_png=False) is None
    print("report self-check OK")


if __name__ == "__main__":
    main()
