"""Naming convention engine and asset-port parsing (phase 3)."""

from __future__ import annotations

import pytest

from app.analysis.naming import (
    MAX_NAME,
    Convention,
    TemplateError,
    clean,
    disambiguate,
    port_tokens,
    service_name,
    validate_template,
    value_token,
)
from app.analysis.recommend import Draft, parse_asset_ports


@pytest.mark.parametrize(
    ("kind", "template", "error"),
    [
        ("planet", "X_<ROLE>", "unknown_kind"),
        ("network_group", "", "template_syntax"),
        ("network_group", "GRP <ROLE>", "template_syntax"),
        ("network_group", "GRP_<role>", "template_syntax"),
        ("network_group", "GRP_STATIC", "template_without_tokens"),
        ("network_group", "GRP_<PORT>", "template_unknown_token"),
        ("rule", "<SRC><DST>", "template_adjacent_tokens"),
        ("rule", "x" * 129, "template_syntax"),
    ],
)
def test_invalid_templates(kind: str, template: str, error: str) -> None:
    with pytest.raises(TemplateError, match=error):
        validate_template(kind, template)


def test_valid_templates() -> None:
    validate_template("network", "NET_<ROLE>_<VALUE>")
    validate_template("port", "SVC_<PROTO>-<PORT>")
    validate_template("rule", "<SRC>_TO_<DST>_<SVC>")


def test_compliance_and_case() -> None:
    c = Convention("rule", "<SRC>_TO_<DST>_<SVC>", "upper")
    assert c.complies("FIN-APP_TO_GOLD-DB_SQL")
    assert not c.complies("fin-app_TO_GOLD-DB_SQL")  # case
    assert not c.complies("WEB_FIN_USERS")  # no _TO_
    assert not c.complies("A_TO_B")  # missing service
    lower = Convention("network_group", "grp_<ROLE>", "lower")
    assert lower.complies("grp_gold")
    assert not lower.complies("GRP_GOLD")
    keep = Convention("network_group", "Grp_<ROLE>", "keep")
    assert keep.complies("Grp_Gold")
    assert not keep.complies("grp_Gold")  # literal part is case-sensitive


def test_render() -> None:
    c = Convention("network", "NET_<ROLE>_<VALUE>", "upper")
    assert c.render({"ROLE": "gold", "VALUE": "10.20.5.0-24"}) == "NET_GOLD_10.20.5.0-24"
    assert c.render({"ROLE": None, "VALUE": "x"}) is None  # unresolved token: no proposal
    assert c.render({"ROLE": "a b/c", "VALUE": "v"}) == "NET_A-B-C_V"  # unsafe characters
    long = Convention("network", "<ROLE>", "keep")
    assert long.render({"ROLE": "x" * (MAX_NAME + 1)}) is None


def test_tokens_and_helpers() -> None:
    assert value_token("host", "10.1.1.5/32") == "10.1.1.5"
    assert value_token("network", "10.20.0.0/16") == "10.20.0.0-16"
    assert value_token("range", "10.0.0.1-10.0.0.9") == "10.0.0.1-10.0.0.9"
    assert value_token("host", None) is None
    assert port_tokens("TCP/1433") == ("TCP", "1433")
    assert port_tokens("TCP/any") == ("TCP", None)
    assert port_tokens("garbage") == (None, None)
    assert service_name(["TCP/1433"], []) == "SQL"
    assert service_name(["TCP/9999"], []) == "TCP9999"
    assert service_name(["TCP/443", "TCP/80"], []) == "HTTPS-HTTP"
    assert service_name([], ["MS-SQL"]) == "MS-SQL"
    assert service_name(["TCP/1433"], ["MS-SQL"]) is None  # mixed: ambiguous
    assert service_name(["TCP/1", "TCP/2", "TCP/3", "TCP/4"], []) is None
    assert service_name(["TCP/any"], []) is None
    assert service_name([], []) is None
    assert clean(" a/b c ") == "a-b-c"
    assert disambiguate("GRP_A", {"grp_a", "GRP_A_2"}) == "GRP_A_3"
    assert disambiguate("GRP_B", {"GRP_A"}) == "GRP_B"


def test_asset_ports() -> None:
    assert parse_asset_ports("TCP 1433") == ["TCP/1433"]
    assert parse_asset_ports("tcp/80, UDP:53; TCP 8000-8080") == [
        "TCP/80",
        "UDP/53",
        "TCP/8000-8080",
    ]
    assert parse_asset_ports("") is None
    assert parse_asset_ports("web ports") is None
    assert parse_asset_ports("TCP 70000") is None
    assert parse_asset_ports("TCP 90-80") is None


def test_fingerprint_ignores_rule_position() -> None:
    def draft(index: int, name: str) -> Draft:
        view = {"id": "r1", "index": index, "name": name, "fields": {}}
        return Draft(
            kind="remove_dead_rule",
            principle="rule_decay",
            title="t",
            priority=1,
            display="inline",
            deploy_cost=1,
            targets=[{"type": "rule", "id": "r1"}],
            preview={"before": [view], "after": [{**view, "status": "removed"}]},
            policy_fmc_id="p",
        )

    assert draft(5, "A").fingerprint() == draft(9, "A").fingerprint()
    assert draft(5, "A").fingerprint() != draft(5, "B").fingerprint()
