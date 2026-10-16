"""
# checks.py
Saved path verifications: the only writes to IP Fabric in this repo. Each CSV row
with a stated intent can be pushed into the Path Verifications table.
"""

from ipfabric import IPFClient

from .lookup import unicast_from_row
from .verdict import expected_passing_traffic


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
