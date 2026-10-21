"""
# bulk.py
Running one CSV row end to end for the `bulk` command: lookup (or resume from saved
files), classify, compare with the stated intent, optionally create the saved
verification and write the report files.

`process_row()` does no printing and is safe to call from several threads at once,
so the command can run rows in parallel; the CLI prints from the main thread.
"""

from collections import Counter
from pathlib import Path
from typing import NamedTuple

from rich.markup import escape

from .checks import build_check_payload, check_exists, create_check
from .lookup import flow_from_row, pivot_note, rerun_unsecured, run_lookup
from .report import fingerprint, flow_name, load_saved_flow, write_flow_report
from .verdict import STATUS_MARKER, STATUSES, classify, evaluate_expectation

# Columns added to the output when --create-path-verifications is used.
WRITE_FIELDS = [
    "create_status",
    "exists",
    "check_id",
    "job_id",
    "expectedPassingTraffic",
]


class Run(NamedTuple):
    """The settings and shared state of one bulk run."""

    ipf_client: object
    zonefw_interfaces: object
    rules: dict | None
    auto_pivot: bool
    has_expected: bool
    create: bool
    force_create: bool
    report_dir: Path | None
    png: bool
    resume: bool


class RowResult(NamedTuple):
    """`out_row` is the CSV row; `note` is extra console text (create / report
    outcome); `resumed` means the lookup was loaded from saved files."""

    out_row: dict
    outcome: dict
    verdict: str
    pivoted: str
    note: str
    resumed: bool


def plan_names(rows: list[dict]) -> list:
    """Report file stem for each row (None for a row that cannot run). Decided up front,
    in input order, so the names do not depend on which thread finishes first."""
    taken, names = set(), []
    for row in rows:
        try:
            names.append(flow_name(flow_from_row(row), taken))
        except ValueError:
            names.append(None)
    return names


def process_row(run: Run, row: dict, name: str | None) -> RowResult:
    """Run one row. Never raises for a bad row or a failed lookup: that becomes an
    ERROR outcome, so one bad flow does not abort the whole file."""
    out_row = dict(row)
    saved = _load_saved(run, row, name)
    if saved:
        outcome, pivoted = saved
        lookup = None
    else:
        outcome, lookup, shown = _score_row(run, row)
        pivoted = pivot_note(lookup.pivot) if lookup else ""

    out_row.update(outcome)
    if run.auto_pivot:
        out_row["auto_pivot"] = pivoted
    verdict = ""
    if run.has_expected:
        verdict = evaluate_expectation(row.get("expected"), outcome["status"])
        out_row["verdict"] = verdict

    note = ""
    if run.create:
        note += _create_row(run, row, out_row, outcome["status"])
    if run.report_dir and name:
        if saved:
            out_row["report"] = f"{name}.md"
        elif lookup:
            note += _report_row(
                run, row, name, out_row, shown, outcome, verdict, pivoted
            )
    return RowResult(out_row, outcome, verdict, pivoted, note, bool(saved))


def _load_saved(run: Run, row: dict, name: str | None):
    """(outcome, pivot note) from an earlier run's files, if --resume and they fit."""
    if not (run.resume and run.report_dir and name):
        return None
    return load_saved_flow(run.report_dir, name, _fingerprint(run, row), run.png)


def _fingerprint(run: Run, row: dict) -> str:
    return fingerprint(
        flow_from_row(row),
        run.ipf_client.snapshot_id,
        run.auto_pivot,
        run.rules is not None,
    )


def _score_row(run: Run, row: dict):
    """Returns (outcome, lookup, shown): the verdict, the lookup it came from, and the
    lookup whose path the report shows. All three are None / error-shaped when the
    row failed.

    The verdict ALWAYS comes from a lookup that stops at the first deny: one that
    simulates past a deny cannot say whether the traffic works. A row with
    `security: continue` additionally gets a continuing lookup for the report, so the
    path beyond the deny is still visible."""
    try:
        flow = flow_from_row(row)
        lookup = run_lookup(
            run.ipf_client.diagram,
            {**flow, "secured_path": True},
            auto_pivot=run.auto_pivot,
        )
        outcome = classify(lookup.result, run.zonefw_interfaces)
        shown = lookup
        if not flow["secured_path"] and run.report_dir:
            shown = rerun_unsecured(run.ipf_client.diagram, lookup)
        return outcome, lookup, shown
    except Exception as error:
        outcome = {
            "status": "ERROR",
            "details": str(error),
            "blocked_at": "",
            "rule": "",
            "branches": 0,
        }
        return outcome, None, None


def _report_row(run, row, name, out_row, shown, outcome, verdict, pivoted):
    """Write a row's report files and record the .md name in the CSV. A failure is
    noted on the console and in the CSV, never fatal to the run."""
    flow = flow_from_row(row)
    extra = {
        "Application": row.get("application"),
        "Intent": row.get("expected"),
        "Verdict": verdict,
        "Pivot": pivoted,
        "Comment": row.get("comment"),
    }
    try:
        png = run.ipf_client.diagram.png(shown.unicast) if run.png else None
        out_row["report"] = write_flow_report(
            run.report_dir,
            name,
            flow,
            shown,
            outcome,
            run.zonefw_interfaces,
            extra,
            png,
            _fingerprint(run, row),
            run.rules,
        )
        return ""
    except Exception as error:
        out_row["report"] = "ERROR"
        return f"  REPORT ERROR {error}"


# ── Path verifications ────────────────────────────────────────────────────────
def _create_row(run: Run, row: dict, out_row: dict, status: str) -> str:
    """Create the saved verification for a row that ran; returns the console note."""
    for field in WRITE_FIELDS:
        out_row.setdefault(field, "")
    if status == "ERROR":
        out_row["create_status"] = "SKIPPED"
        return "  SKIPPED (row failed)"
    try:
        return "  " + create_one(run.ipf_client, row, out_row, run.force_create)
    except Exception as error:
        out_row["create_status"] = "ERROR"
        return f"  CREATE ERROR {error}"


def create_one(ipf_client, row, out_row, force_create):
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


# ── Output ────────────────────────────────────────────────────────────────────
def output_fields(rows, has_expected, auto_pivot, create, report_dir):
    """Output columns: the input ones, then the result ones that apply to this run."""
    fields = list(rows[0].keys())
    added = ["status", "verdict", "blocked_at", "rule", "branches", "details"]
    if not has_expected:
        added.remove("verdict")
    if auto_pivot:
        added.append("auto_pivot")
    if report_dir:
        added.append("report")
    if create:
        added.extend(WRITE_FIELDS)
    fields.extend(f for f in added if f not in fields)
    return fields


def result_line(res: RowResult) -> str:
    """The result half of a console line: `✓ REACHED [MATCH] details  [notes]`."""
    marker = STATUS_MARKER.get(res.outcome["status"], "?")
    tag = f"[{res.verdict}] " if res.verdict else ""
    detail = res.outcome["details"]
    pivot_tag = f"  [auto-pivot {res.pivoted}]" if res.pivoted else ""
    resumed = "  [resumed]" if res.resumed else ""
    # escape(): details are full of '[zone-deny]' / '[fw]', which rich would
    # swallow as style markup — the CSV kept them, the console silently did not.
    return escape(
        f"{marker} {res.outcome['status']:<8} {tag}"
        f"{detail[:90]}{'…' if len(detail) > 90 else ''}{res.note}{pivot_tag}{resumed}"
    )


def summary_line(output_file, results, has_expected, create):
    """The closing `→ file  STATUS: n ...` line."""
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
    if create:
        made = Counter(r.get("create_status", "") for r in results)
        line += "   |  verifications → " + "  ".join(
            f"{k}: {v}" for k, v in made.items() if k
        )
    return line
