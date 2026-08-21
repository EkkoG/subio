import pytest

from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.adapters.target import TargetValidationService
from subio_v2.core.nodes import (
    DirectNode,
    HttpNode,
    Protocol,
    ShadowTLSSettings,
    SurgePolicyOptions,
    WireguardNode,
)


@pytest.mark.parametrize(
    ("surge_value", "generic_value"),
    [
        ("dual", None),
        ("v4-only", "ipv4"),
        ("v6-only", "ipv6"),
        ("prefer-v4", "ipv4-prefer"),
        ("prefer-v6", "ipv6-prefer"),
    ],
)
def test_surge_ip_version_maps_to_generic_and_back(surge_value, generic_value):
    parsed = SurgeParser().parse_result(
        f"node = http, example.com, 80, ip-version={surge_value}"
    )

    assert parsed.issues == []
    assert parsed.nodes[0].ip_version == generic_value
    output = SurgeEmitter().emit_result(parsed.nodes)
    assert output.errors == []
    if surge_value == "dual":
        assert "ip-version=" not in output.content
    else:
        assert f"ip-version={surge_value}" in output.content


def test_surge_ip_version_rejects_unknown_value():
    result = SurgeParser().parse_result(
        "node = http, example.com, 80, ip-version=prefer-v7"
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.protocol-parameter"
    assert result.issues[0].field == "lines[0]"


@pytest.mark.parametrize(
    "parameter",
    [
        "allow-other-interface=maybe",
        "hybrid=maybe",
        "tos=999",
        "test-timeout=0",
        "test-udp=",
        "server-cert-fingerprint-sha256=AA:BB",
    ],
)
def test_surge_common_parameters_are_strictly_rejected(parameter):
    result = SurgeParser().parse_result(
        f"node = https, example.com, 443, {parameter}"
    )

    assert result.nodes == []
    assert result.issues[0].severity.value == "error"
    assert result.issues[0].code == "parse.protocol-parameter"


def test_builtin_policy_names_are_reserved_even_with_non_alias_rhs():
    result = SurgeParser().parse_result(
        "DIRECT = http, example.com, 80\nCELLULAR = http, example.com, 80"
    )

    assert result.nodes == []
    assert [issue.code for issue in result.issues] == [
        "parse.ignored-built-in-redefinition",
        "parse.invalid-built-in-redefinition",
    ]


def test_surge_target_checks_common_applicability_and_shadow_tls_protocols():
    direct = DirectNode(
        name="direct",
        type=Protocol.DIRECT,
        dialer_proxy="upstream",
        surge_options=SurgePolicyOptions(no_error_alert=True),
    )
    direct_result = TargetValidationService("surge").check_node(direct)
    assert not direct_result.supported
    assert {issue.field for issue in direct_result.warnings} >= {
        "dialer_proxy",
        "surge_options.no_error_alert",
    }

    wireguard = WireguardNode(
        name="wg",
        type=Protocol.WIREGUARD,
        server="example.com",
        port=51820,
        private_key="private",
        interface_name="en0",
    )
    assert not TargetValidationService("surge").check_node(wireguard).supported

    http = HttpNode(
        name="http",
        type=Protocol.HTTP,
        server="example.com",
        port=80,
        shadow_tls=ShadowTLSSettings(password="secret"),
    )
    assert TargetValidationService("surge").check_node(http).supported
