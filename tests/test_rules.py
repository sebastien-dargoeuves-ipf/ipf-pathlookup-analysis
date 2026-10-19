"""
Self-check for modules/rules.py — run it with `python tests/test_rules.py`.
No pytest, no server: a fake client stands in for IP Fabric and counts the calls. It
checks what keeps the module cheap (denies only, one call per distinct rule) and what
keeps it honest (unambiguous match only, action must agree with the verdict).

The ACI cases are SYNTHETIC: the lab used to develop this has no APIC data, so they only
prove the logic follows the column names the path-analyzer tool reads, not real output.
"""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.pathgraph import _forwarding_text
from modules.rules import Rules, _rule_number


class FakeTable:
    def __init__(self, rows, fail=False):
        self.rows, self.fail, self.calls = rows, fail, 0

    def all(self, columns=None, filters=None):
        self.calls += 1
        if self.fail:
            raise RuntimeError("boom")
        want = {k: v[1] for f in filters["and"] for k, v in f.items()}
        return [r for r in self.rows if all(r.get(k) == v for k, v in want.items())]


class FakeClient:
    def __init__(self, acl=(), zonefw=(), epgs=(), apic_fails=False):
        self.acl, self.zonefw = FakeTable(list(acl)), FakeTable(list(zonefw))
        self.technology = SimpleNamespace(
            security=SimpleNamespace(acl=self.acl, zone_firewall_policies=self.zonefw)
        )
        self._epgs, self._apic_fails, self.epg_calls = list(epgs), apic_fails, 0

    def fetch_all(self, url, columns=None, filters=None):
        self.epg_calls += 1
        if self._apic_fails:
            raise RuntimeError("no such table")
        return [e for e in self._epgs if str(e["pcTag"]) == filters["pcTag"][1]]


def row(number, action, host="fw1", policy="P", **extra):
    return {"hostname": host, "policyName": policy, "ruleNumber": number, "action": action,
            "ipProtocol": ["tcp"], "ipSrc": ["10.0.0.0/24"], "ipDst": [], "dstPorts": ["3389"],
            **extra}


def sec(rule, result="ACL_DENY", severity=30, type_="acl", policy="P", ignored=False):
    return {"type": type_, "policy": policy, "rule": rule, "result": result,
            "severity": severity, "ignored": ignored}


def main():
    # ── Cost: denies only, one call per distinct rule, however many paths hit it ──
    client = FakeClient(acl=[row(8, "deny"), row(5, "allow"), row(5, "allow")],
                        zonefw=[row(2, "deny", ruleName="rdp")])
    rules = Rules(client)
    text = "deny tcp/3389 10.0.0.0/24 → any"
    assert rules.detail("fw1", sec([0, 1, 8])) == text
    assert rules.detail("fw1", sec([0, 2, 8])) == text      # another path, same rule
    assert client.acl.calls == 1, client.acl.calls
    assert rules.detail("fw1", sec([1, 0, 2], "ZONEFW_DENY", type_="zoneFw")) == (
        "deny tcp/3389 10.0.0.0/24 → any (rdp)")
    assert rules.detail("fw2", sec([0, 1, 8])) is None       # other device: a new call
    assert client.acl.calls == 2

    before = client.acl.calls
    assert rules.detail("fw1", sec([0, 1, 8], "ACL_PERMIT", 0)) is None   # permit
    assert rules.detail("fw1", sec([0, 1, 8], severity=30, ignored=True)) is None
    assert rules.detail("fw1", sec([0, 1], "NAT44_DENY", type_="nat44")) is None
    assert rules.detail("fw1", sec([], "ACL_DENY")) is None
    assert client.acl.calls == before, "permits / ignored / nat / no rule must not query"

    # ── Honesty: no confident match -> no detail ──
    assert rules.detail("fw1", sec([0, 1, 9])) is None                      # no such rule
    assert rules.detail("fw1", sec([0, 1, 5])) is None                      # two rows
    assert rules.detail("fw1", sec([0, 1, 8], policy="Q")) is None          # other policy
    allow_only = Rules(FakeClient(acl=[row(3, "allow")]))
    assert allow_only.detail("fw1", sec([0, 1, 3])) is None                 # deny vs allow row
    assert Rules(FakeClient(acl=[row(8, "deny")]))._client.acl.calls == 0   # nothing eager

    # ── A failing table must not fail the flow ──
    broken = Rules(SimpleNamespace(technology=SimpleNamespace(security=SimpleNamespace(
        acl=FakeTable([], fail=True)))))
    assert broken.detail("fw1", sec([0, 1, 8])) is None

    # ── ruleNumber convention (same as the path-analyzer tool) ──
    assert (_rule_number([0, 1, 8]), _rule_number([4, 7]), _rule_number([6])) == (8, 4, 6)

    # ── ACI (synthetic): a contract is an acl row with group tags and a VNI ──
    aci = row(3, "deny", host="leaf1", ipProtocol=[], ipSrc=[], dstPorts=[], tcpDst=["443"],
              vxlanSrcGrp=["16386"], vxlanDstGrp=["prefGrMemb: 32770,49153"], vxlanVni=[5003])
    epgs = [{"pcTag": 16386, "name": "web", "tenant": "T1"},
            {"pcTag": 32770, "name": "db", "tenant": "T1"}]
    client = FakeClient(acl=[aci], epgs=epgs)
    rules = Rules(client)
    got = rules.detail("leaf1", sec([0, 0, 3]))
    assert got == "deny tcp/443 web (T1) → db (T1),49153 vni 5003", got   # unknown tag stays a tag
    calls = client.epg_calls
    rules.detail("leaf1", sec([0, 0, 3]))
    assert client.epg_calls == calls, "EPG names are cached"
    no_apic = Rules(FakeClient(acl=[aci], apic_fails=True))
    assert no_apic.detail("leaf1", sec([0, 0, 3])) == "deny tcp/443 16386 → 32770,49153 vni 5003"

    # ── The VXLAN header names the group even without any lookup ──
    ev = SimpleNamespace(type="insert header", headerType="vxlan",
                         header={"vni": 5003, "groupPolicyId": 16386})
    assert _forwarding_text(ev) == "push vxlan vni 5003 group 16386"
    assert _forwarding_text(ev, rules.epg) == "push vxlan vni 5003 group web (T1)"
    print("rules self-check OK")


if __name__ == "__main__":
    main()
