import pytest

from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.adapters.clash_family.emitter import ClashEmitter
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


def test_http_headers_use_official_semicolon_syntax_without_duplicate_output():
    result = SurgeParser().parse_result(
        'proxy = https, example.com, 443, headers="User-Agent:SubIO;X-Test:a=b", always-use-connect=true'
    )

    assert result.issues == []
    node = result.nodes[0]
    assert node.headers == {"User-Agent": "SubIO", "X-Test": "a=b"}
    assert node.always_use_connect is True

    emission = SurgeEmitter().emit_result(result.nodes)
    assert emission.errors == []
    assert emission.content.count("headers=") == 1
    assert "headers=User-Agent:SubIO;X-Test:a=b" in emission.content
    assert "always-use-connect=true" in emission.content


@pytest.mark.parametrize("keyword", ["ss", "snell"])
def test_obfs_uri_round_trips_as_typed_surge_field(keyword):
    if keyword == "ss":
        line = (
            "proxy = ss, example.com, 8388, encrypt-method=aes-256-gcm, "
            "password=p, obfs=http, obfs-uri=https://obfs.example/path"
        )
    else:
        line = (
            "proxy = snell, example.com, 443, psk=p, version=5, obfs=http, "
            "obfs-uri=https://obfs.example/path"
        )

    result = SurgeParser().parse_result(line)
    assert result.issues == []
    assert result.nodes[0].obfs_uri == "https://obfs.example/path"
    output = SurgeEmitter().emit_result(result.nodes)
    assert output.errors == []
    assert "obfs-uri=https://obfs.example/path" in output.content


def test_surge_only_fields_produce_cross_target_diagnostics():
    http = SurgeParser().parse_result(
        'proxy = https, example.com, 443, headers="User-Agent:SubIO", always-use-connect=true'
    ).nodes[0]
    result = ClashEmitter().emit_result([http])
    assert result.supported_nodes == [http]
    assert any(issue.field == "always_use_connect" for issue in result.issues)

    ss = SurgeParser().parse_result(
        "proxy = ss, example.com, 8388, encrypt-method=aes-256-gcm, password=p, obfs=http, obfs-uri=https://obfs.example/path"
    ).nodes[0]
    result = ClashEmitter().emit_result([ss])
    assert any(issue.field == "obfs_uri" for issue in result.issues)


def test_vmess_cipher_and_snell_value_domains_are_strict():
    invalid_vmess = SurgeParser().parse_result(
        "vmess = vmess, example.com, 443, username=u, encrypt-method=auto"
    )
    assert invalid_vmess.nodes == []
    assert invalid_vmess.issues[0].code == "parse.protocol-parameter"

    invalid_snell = SurgeParser().parse_result(
        "snell = snell, example.com, 443, psk=p, version=5, udp-port=0"
    )
    assert invalid_snell.nodes == []
    assert invalid_snell.issues[0].code == "parse.protocol-parameter"

    valid_snell = SurgeParser().parse_result(
        "snell = snell, example.com, 443, psk=p, version=6, udp-port=8443, mode=quic"
    )
    assert valid_snell.issues == []


@pytest.mark.parametrize(
    "line",
    [
        "tuic = tuic-v5, example.com, 443, uuid=u, password=p, shadow-tls-password=s",
        "wg = wireguard, section-name=office, shadow-tls-password=s",
    ],
)
def test_shadow_tls_rejects_inapplicable_surge_protocols(line):
    result = SurgeParser().parse_result(line)
    assert result.nodes == []
    assert result.issues[0].code == "parse.protocol-parameter"
