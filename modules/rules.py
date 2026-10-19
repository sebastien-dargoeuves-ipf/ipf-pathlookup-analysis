"""
# rules.py
The rule behind a security event, in words. Opt-in (`--security-detail`): without it
nothing here runs and only what the pathlookup JSON carries is shown.

A `security check` event only has the policy name and rule numbers
(`'LAN_TO_WAN' rule=[0, 1, 8]`). The rule itself is in IP Fabric's ACL / zone-firewall
policy tables. `Rules` asks for ONE rule at a time (device + policy + number), only for
denies, and remembers every answer, so a bulk run costs one small call per distinct rule
that blocks something, whatever the table sizes or the number of flows.

ACI: a contract is an ordinary `acl` check on a leaf switch. Its rule row names source and
destination by group tag (pcTag) instead of by address and carries the VXLAN VNI; the tags
resolve to EPG names through the APIC endpoint-groups table (empty or absent without ACI).

The row is `ruleNumber == _rule_number(decidingRule)` for the same device and policy.
Checked on live data (ACL [0,1,8] -> rule 8, zone-firewall [1,0,2] -> rule 2 and [1,0,1]
-> rule 1, each fitting the flow that produced it), but IP Fabric does not document it, so
a rule is attached only when exactly one row matches and its action agrees with the
verdict. Otherwise there is no detail, never a wrong one.
"""

from threading import Lock

# securityType in the event -> the table that holds its rules.
_TABLES = {"acl": "acl", "zoneFw": "zone_firewall_policies"}
_COLUMNS = [
    "hostname", "policyName", "ruleNumber", "ruleName", "description",
    "action", "ipProtocol", "ipSrc", "ipDst", "dstPorts",
    "tcpDst", "udpDst", "vxlanVni", "vxlanSrcGrp", "vxlanDstGrp",  # ACI
]
_SEVERITY_RED = 30


class Rules:
    """On-demand, cached rule lookups. Safe to share between threads."""

    def __init__(self, ipf_client):
        self._client = ipf_client
        self._rules = {}  # (type, host, policy, number) -> rows
        self._epgs = {}   # pcTag -> EPG label or None
        self._lock = Lock()

    def detail(self, hostname: str, sec: dict) -> str | None:
        """The deciding rule in words (`deny tcp/3389 172.20.22.0/24 → any`), or None.
        Only denies are looked up: `sec` is a pathgraph security entry."""
        denies = (sec["severity"] or 0) >= _SEVERITY_RED and not sec["ignored"]
        if not (denies and sec["rule"] and sec["type"] in _TABLES):
            return None
        rows = self._rows(sec["type"], hostname, sec["policy"], _rule_number(sec["rule"]))
        if len(rows) != 1 or not _agrees(rows[0]["action"], sec["result"]):
            return None
        return _rule_text(rows[0], self)

    def epg(self, tag) -> str | None:
        """`web (Tenant1)` for an ACI group tag (pcTag / group policy ID), or None."""
        tag = str(tag)
        with self._lock:
            if tag in self._epgs:
                return self._epgs[tag]
        label = None
        try:
            found = self._client.fetch_all(
                "tables/apic/endpoint-groups",
                columns=["pcTag", "name", "tenant"],
                filters={"pcTag": ["eq", tag]},
            )
            if found and found[0].get("name"):
                tenant = found[0].get("tenant")
                label = f"{found[0]['name']} ({tenant})" if tenant else found[0]["name"]
        except Exception:  # no ACI on this instance: not an error, just no names
            pass
        with self._lock:
            self._epgs[tag] = label
        return label

    def _rows(self, kind, hostname, policy, number) -> list:
        key = (kind, hostname, policy, number)
        with self._lock:
            if key in self._rules:
                return self._rules[key]
        table = getattr(self._client.technology.security, _TABLES[kind])
        try:
            rows = table.all(
                columns=_COLUMNS,
                filters={"and": [
                    {"hostname": ["eq", hostname]},
                    {"policyName": ["eq", policy]},
                    {"ruleNumber": ["eq", number]},
                ]},
            )
        except Exception:  # detail is a nicety: a failed lookup must not fail the flow
            rows = []
        with self._lock:
            self._rules[key] = rows
        return rows


def rule_detail(rules: Rules | None, hostname: str, sec: dict) -> str | None:
    """`Rules.detail`, tolerating "no --security-detail" (rules is None)."""
    return rules.detail(hostname, sec) if rules else None


def epg_label(rules: Rules | None, tag) -> str | None:
    """`Rules.epg`, tolerating "no --security-detail" (rules is None)."""
    return rules.epg(tag) if rules else None


def _rule_number(rule: list) -> int:
    """The ruleNumber inside `decidingRule`: its third number, or its first when it has
    fewer (same convention as the path-analyzer tool; every ACL and zone-firewall case
    seen live has three, where it is also the last)."""
    return rule[2] if len(rule) >= 3 else rule[0]


def _agrees(action: str, result: str | None) -> bool:
    """A deny verdict needs a deny rule."""
    return action == "deny" if result and result.endswith("_DENY") else True


def _items(values, limit=3) -> str:
    values = list(values or [])
    if not values:
        return "any"
    extra = len(values) - limit
    return ",".join(values[:limit]) + (f" (+{extra})" if extra > 0 else "")


def _groups(values, rules: Rules) -> str:
    """ACI group tags as EPG names (`web (T1)`), falling back to the tag. A
    `prefGrMemb: 1,2,3` entry (preferred-group members) is flattened to its tags."""
    names = []
    for value in values:
        text = str(value)
        tags = text.replace("prefGrMemb:", "").split(",") if "prefGrMemb" in text else [text]
        names += [rules.epg(t.strip()) or t.strip() for t in tags if t.strip()]
    return _items(names)


def _rule_text(row: dict, rules: Rules) -> str:
    """`deny tcp/3389 10.0.0.0/24 → any`; for an ACI contract the endpoints are EPGs
    and the VNI is appended."""
    ports = row.get("dstPorts") or row.get("tcpDst") or row.get("udpDst") or []
    proto = ",".join(row.get("ipProtocol") or [])
    if not proto:
        proto = "tcp" if row.get("tcpDst") else "udp" if row.get("udpDst") else "any"
    port_text = f"/{','.join(map(str, ports))}" if ports else ""
    src = _groups(row["vxlanSrcGrp"], rules) if row.get("vxlanSrcGrp") else _items(row.get("ipSrc"))
    dst = _groups(row["vxlanDstGrp"], rules) if row.get("vxlanDstGrp") else _items(row.get("ipDst"))
    text = f"{row['action']} {proto}{port_text} {src} → {dst}"
    if row.get("vxlanVni"):
        text += f" vni {','.join(map(str, row['vxlanVni']))}"
    name = row.get("ruleName") or row.get("description")
    return f"{text} ({name})" if name else text
