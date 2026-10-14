"""
# verdict.py
Turn one path lookup into a one-line outcome, and compare it against the intent
stated for that flow.

This is what the bulk CSV runner reports per row. It reads the SDK's typed
`PathLookupResult` through `pathgraph`, never the raw response JSON.

Two separate questions live here, and they are answered from different data:

- *What happened?* -> `classify()`: REACHED / PARTIAL / BLOCKED / NO-PATH / ERROR.
- *Was that what we wanted?* -> `evaluate_expectation()`: MATCH / MISMATCH / ASSESS.

`expected_passing_traffic()` maps the same intent vocabulary onto the value IP
Fabric wants when the flow is pushed into the Path Verifications table.
"""

from .pathgraph import blocked_hops, branch_count, destinations, dropped_packets, enrich

STATUSES = ("REACHED", "PARTIAL", "BLOCKED", "NO-PATH", "ERROR")
STATUS_MARKER = {
    "REACHED": "✓",
    "PARTIAL": "◐",
    "BLOCKED": "⛔",
    "NO-PATH": "✗",
    "ERROR": "!",
}

# Firewall/ACL deny flags, as opposed to routing flags like 'no-dgw'. This is what
# separates BLOCKED (a policy said no) from NO-PATH (nothing knew where to send it).
SECURITY_FLAGS = {"zone-deny", "acl-deny", "policy-deny"}

# One intent vocabulary, shared by the verdict and the create paths. Previously two
# copies with quietly different membership.
EXPECTED_ALLOW = {
    "allow", "allowed", "pass", "permit", "permitted",
    "reach", "reached", "yes", "ok", "all",
}
EXPECTED_BLOCK = {"block", "blocked", "deny", "denied", "no", "none"}
EXPECTED_PART = {"part", "partial", "some"}
# 'assess' states no pass/fail intent — surface the outcome, assert nothing.
EXPECTED_ASSESS = {"assess", "check", "info", "fyi", "review", "observe", "report"}

# An intent is satisfied only by a FULL outcome. PARTIAL satisfies neither allow nor
# block — it is a partial leak or a partial outage, and both deserve a MISMATCH.
_SATISFIED_BY = {
    "allow": {"REACHED"},
    "block": {"BLOCKED", "NO-PATH"},
    "part": {"PARTIAL"},
}

_PASSING_TRAFFIC = {"allow": "all", "block": "none", "part": "part"}


def normalise_expected(raw):
    """The stated intent, as one of 'allow' / 'block' / 'part' / 'assess'.

    Returns '' when the cell is empty (no intent stated — different from 'assess',
    which is a deliberate "just tell me"), or '?' when the value is unrecognised."""
    value = (raw or "").strip().lower()
    if not value:
        return ""
    for intent, synonyms in (
        ("allow", EXPECTED_ALLOW),
        ("block", EXPECTED_BLOCK),
        ("part", EXPECTED_PART),
        ("assess", EXPECTED_ASSESS),
    ):
        if value in synonyms:
            return intent
    return "?"


def evaluate_expectation(raw, status):
    """Compare a stated intent against the actual status.

    '' (nothing stated), 'MATCH', 'MISMATCH', 'ASSESS' (observed, not scored),
    'n/a' (status was ERROR, nothing to judge) or '?' (unrecognised intent)."""
    intent = normalise_expected(raw)
    if intent in ("", "?", "assess"):
        return {"": "", "?": "?", "assess": "ASSESS"}[intent]
    if status == "ERROR":
        return "n/a"
    return "MATCH" if status in _SATISFIED_BY[intent] else "MISMATCH"


def expected_passing_traffic(raw):
    """`expectedPassingTraffic` for a saved path verification, or None when the
    flow must not be created.

    Returning None for an empty cell is deliberate. Defaulting it to "all" would
    turn a row where nobody stated an intent into a permanent assertion that the
    flow must fully pass — which surfaces months later as a failing verification
    with no one able to say who asked for it. 'assess' is likewise not creatable:
    IP Fabric requires an explicit expected result."""
    return _PASSING_TRAFFIC.get(normalise_expected(raw))


def _destination_text(hop):
    """'10.2.0.222:443' for a hop the traffic reached, falling back to the device
    label when the arriving edge carried no IP header."""
    delivered = hop["delivered"]
    ips = ", ".join(delivered["ips"]) if delivered["ips"] else hop["device"]
    ports = ", ".join(delivered["ports"])
    return f"{ips}:{ports}" if ports else ips


def _drop_text(drops):
    """'d1xfw01 [fw] on ge-0/0/3.0 (ports: 3389)', one per dropping device."""
    parts = []
    for drop in drops:
        ports = f" (ports: {', '.join(drop['ports'])})" if drop["ports"] else ""
        parts.append(
            f"{drop['device']} [{drop['type']}] on {', '.join(drop['ifaces'])}{ports}"
        )
    return "; ".join(parts)


def _rule_text(block):
    """The deciding rule at a blocked hop, for the `rule` column."""
    for deny in block["denies"]:
        return f"{deny['type']} '{deny['policy']}' rule={deny['rule']} → {deny['result']}"
    return block["drop_reason"] or ""


def classify(res, zonefw_interfaces=None):
    """Outcome of one path lookup.

    Returns status / details / blocked_at / rule / branches. `status` follows
    `pathlookup.passingTraffic`; `details` leads with what actually reached the
    destination, because that is the thing a reviewer needs first."""
    pathlookup = res.pathlookup
    passing = pathlookup.passingTraffic if pathlookup else None
    if passing is None and not res.nodes:
        return {
            "status": "ERROR",
            "details": "Empty response – no path data returned",
            "blocked_at": "",
            "rule": "",
            "branches": 0,
        }

    flags = list(pathlookup.eventsSummary.flags) if pathlookup else []
    flag_info = f" [{', '.join(flags)}]" if flags else ""

    # No edges means nothing ever left the source, whatever passingTraffic claims.
    # Trusting the field alone here would report REACHED for an empty graph.
    if not res.edges:
        return {
            "status": "NO-PATH",
            "details": f"No path to destination{flag_info} – routing/reachability issue",
            "blocked_at": "",
            "rule": "",
            "branches": 0,
        }

    structure = enrich(res, zonefw_interfaces)
    # dict.fromkeys dedupes while keeping order: ECMP means the same destination is
    # reached once per leg, and "reached X; reached X" tells a reader nothing.
    arrived = list(
        dict.fromkeys(_destination_text(hop) for hop in destinations(structure))
    )
    drops = dropped_packets(res)
    blocks = blocked_hops(res, zonefw_interfaces)

    if passing == "all":
        status = "REACHED"
        details = "Reached " + ("; ".join(arrived) if arrived else "destination")
    elif passing == "part":
        status = "PARTIAL"
        details = "Reached " + ("; ".join(arrived) if arrived else "part of destination")
        details += (
            f"; denied{flag_info}: " + _drop_text(drops)
            if drops
            else f"; remainder not reached{flag_info}"
        )
    elif drops or (set(flags) & SECURITY_FLAGS):
        status = "BLOCKED"
        details = f"Blocked{flag_info}: {_drop_text(drops) or 'security policy'}"
    else:
        status = "NO-PATH"
        details = f"No path to destination{flag_info} – routing/reachability issue"

    return {
        "status": status,
        "details": details,
        "blocked_at": "; ".join(f"{b['device']} [{b['type']}]" for b in blocks),
        "rule": "; ".join(filter(None, (_rule_text(b) for b in blocks))),
        "branches": branch_count(structure),
    }
