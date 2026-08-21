import pytest

from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.adapters.clash_family.emitter import ClashEmitter
from subio_v2.adapters.target import TargetValidationService
from subio_v2.core.nodes import (
    DirectNode,
    HttpNode,
    HttpVariant,
    MasqueNode,
    Protocol,
    RejectNode,
    ShadowTLSSettings,
    ShadowsocksNode,
    SurgePolicyOptions,
    TrustTunnelNode,
    WireguardNode,
    VmessNode,
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
        "ecn=maybe",
        "block-quic=maybe",
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


@pytest.mark.parametrize(
    "parameter",
    [
        "hybrid=auto",
        "hybrid=on",
        "hybrid=off",
        "hybrid=true",
        "hybrid=false",
        "ecn=auto",
        "ecn=on",
        "ecn=off",
        "ecn=true",
        "ecn=false",
        "block-quic=auto",
        "block-quic=on",
        "block-quic=off",
    ],
)
def test_surge_common_enum_parameters_accept_official_values(parameter):
    result = SurgeParser().parse_result(
        f"node = https, example.com, 443, {parameter}"
    )

    assert result.issues == []


@pytest.mark.parametrize("value", ["000255", "0x000000ff"])
def test_surge_tos_accepts_leading_zero_representations(value):
    result = SurgeParser().parse_result(
        f"node = https, example.com, 443, tos={value}"
    )

    assert result.issues == []


def test_surge_typed_common_options_accept_official_domains():
    node = HttpNode(
        name="typed",
        type=Protocol.HTTP,
        server="example.com",
        port=443,
        surge_options=SurgePolicyOptions(
            hybrid="true",
            ecn="false",
            block_quic="auto",
            tos="0x000000ff",
            test_udp="probe.example@198.51.100.1",
        ),
    )

    assert TargetValidationService("surge").check_node(node).supported


@pytest.mark.parametrize(
    "value",
    [
        "probe.example",
        "probe.example@2001:db8::1",
        "probe.example@198.51.100.1@198.51.100.2",
        "probe.example@256.51.100.1",
    ],
)
def test_surge_test_udp_requires_hostname_and_ipv4(value):
    result = SurgeParser().parse_result(
        f"node = https, example.com, 443, test-udp={value}"
    )

    assert result.nodes == []
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


@pytest.mark.parametrize("name", ["DIRECT", "CELLULAR"])
def test_surge_typed_nodes_cannot_use_builtin_policy_names(name):
    node = DirectNode(name=name, type=Protocol.DIRECT)

    result = TargetValidationService("surge").check_node(node)

    assert not result.supported
    assert any(
        issue.code == "conversion.reserved-policy-name" and issue.field == "name"
        for issue in result.warnings
    )


def test_surge_typed_lowercase_reserved_policy_name_is_rejected_before_emit():
    node = DirectNode(name="direct", type=Protocol.DIRECT)

    check = TargetValidationService("surge").check_node(node)
    assert not check.supported
    assert any(issue.code == "conversion.reserved-policy-name" for issue in check.warnings)

    emission = SurgeEmitter().emit_result([node])
    assert emission.supported_nodes == []
    assert emission.content == ""
    assert emission.errors[0].code == "conversion.reserved-policy-name"


@pytest.mark.parametrize("udp_port", [0, -1, 65536, True])
def test_surge_typed_shadowsocks_udp_port_is_bounded(udp_port):
    node = ShadowsocksNode(
        name="ss",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        password="p",
        udp_port=udp_port,
    )

    result = TargetValidationService("surge").check_node(node)

    assert not result.supported
    assert any(issue.field == "udp_port" for issue in result.warnings)


def test_surge_typed_masque_rejects_port_hopping_with_underlying_proxy():
    node = MasqueNode(
        name="masque",
        type=Protocol.MASQUE,
        server="example.com",
        port=443,
        ports="1000-2000",
        dialer_proxy="upstream",
    )

    result = TargetValidationService("surge").check_node(node)

    assert not result.supported
    assert any(issue.field == "ports" for issue in result.warnings)


def test_surge_target_checks_common_applicability_and_shadow_tls_protocols():
    direct = DirectNode(
        name="local-direct",
        type=Protocol.DIRECT,
        dialer_proxy="upstream",
        surge_options=SurgePolicyOptions(no_error_alert=True, ecn="on"),
    )
    direct_result = TargetValidationService("surge").check_node(direct)
    assert not direct_result.supported
    assert {issue.field for issue in direct_result.warnings} >= {
        "dialer_proxy",
        "surge_options.no_error_alert",
        "surge_options.ecn",
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

    trust = TrustTunnelNode(
        name="trust",
        type=Protocol.TRUSTTUNNEL,
        server="example.com",
        port=443,
        udp=False,
        username="user",
        password="password",
        shadow_tls=ShadowTLSSettings(password="secret"),
    )
    assert TargetValidationService("surge").check_node(trust).supported

    trust.quic = True
    assert not TargetValidationService("surge").check_node(trust).supported


@pytest.mark.parametrize("protocol", ["direct", "reject", "reject-drop"])
def test_surge_raw_aliases_reject_ecn(protocol):
    result = SurgeParser().parse_result(f"local = {protocol}, ecn=on")

    assert result.nodes == []
    assert result.issues[0].code == "parse.protocol-parameter"
    assert "ecn is only supported by proxy policies" in result.issues[0].message


@pytest.mark.parametrize("node_type", [Protocol.DIRECT, Protocol.REJECT])
def test_surge_typed_aliases_reject_ecn(node_type):
    node = (
        DirectNode(name="local-direct", type=node_type)
        if node_type == Protocol.DIRECT
        else RejectNode(name="local-reject", type=node_type)
    )
    node.surge_options = SurgePolicyOptions(ecn="on")

    result = TargetValidationService("surge").check_node(node)

    assert not result.supported
    assert any(issue.field == "surge_options.ecn" for issue in result.warnings)


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


def test_h2_connect_headers_use_semicolon_syntax_without_duplicate_output():
    result = SurgeParser().parse_result(
        'proxy = h2-connect, example.com, 443, headers="One:1;Two:2"'
    )

    assert result.issues == []
    node = result.nodes[0]
    assert node.headers == {"One": "1", "Two": "2"}

    emission = SurgeEmitter().emit_result(result.nodes)

    assert emission.errors == []
    assert emission.content.count("headers=") == 1
    assert "headers=One:1;Two:2" in emission.content


def test_h2_connect_rejects_always_use_connect():
    result = SurgeParser().parse_result(
        "proxy = h2-connect, example.com, 443, always-use-connect=true"
    )

    assert result.nodes == []
    assert result.issues[0].code == "parse.protocol-parameter"
    assert "only supported by Surge http/https" in result.issues[0].message

    node = HttpNode(
        name="h2",
        type=Protocol.HTTP,
        server="example.com",
        port=443,
        variant=HttpVariant.H2_CONNECT,
        always_use_connect=True,
    )
    check = TargetValidationService("surge").check_node(node)
    assert not check.supported
    assert any(issue.field == "always_use_connect" for issue in check.warnings)


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


@pytest.mark.parametrize("keyword", ["ss", "snell"])
def test_obfs_uri_accepts_relative_safe_value(keyword):
    if keyword == "ss":
        line = (
            "proxy = ss, example.com, 8388, encrypt-method=aes-256-gcm, "
            "password=p, obfs=http, obfs-uri=/obfs/path"
        )
    else:
        line = (
            "proxy = snell, example.com, 443, psk=p, version=5, obfs=http, "
            "obfs-uri=/obfs/path"
        )

    result = SurgeParser().parse_result(line)
    assert result.issues == []
    assert result.nodes[0].obfs_uri == "/obfs/path"


@pytest.mark.parametrize("keyword", ["ss", "snell"])
def test_obfs_uri_rejects_tls_obfs_mode(keyword):
    if keyword == "ss":
        line = (
            "proxy = ss, example.com, 8388, encrypt-method=aes-256-gcm, "
            "password=p, obfs=tls, obfs-uri=/obfs/path"
        )
    else:
        line = (
            "proxy = snell, example.com, 443, psk=p, version=5, obfs=tls, "
            "obfs-uri=/obfs/path"
        )

    result = SurgeParser().parse_result(line)
    assert result.nodes == []
    assert result.issues[0].code == "parse.protocol-parameter"


def test_surge_typed_obfs_uri_requires_http_mode():
    node = ShadowsocksNode(
        name="ss",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="aes-256-gcm",
        password="p",
        plugin="obfs",
        plugin_opts={"mode": "http", "host": "example.com"},
        obfs_uri="/obfs/path",
    )

    assert TargetValidationService("surge").check_node(node).supported
    node.plugin_opts["mode"] = "tls"
    assert not TargetValidationService("surge").check_node(node).supported


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
    assert "uri" not in result.content["proxies"][0].get("plugin-opts", {})


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
        "snell = snell, example.com, 443, psk=p, version=6, udp-port=8443, mode=unshaped"
    )
    assert valid_snell.issues == []

    invalid_snell_mode = SurgeParser().parse_result(
        "snell = snell, example.com, 443, psk=p, version=6, mode=quic"
    )
    assert invalid_snell_mode.nodes == []
    assert invalid_snell_mode.issues[0].code == "parse.protocol-parameter"


def test_mihomo_vmess_auto_uses_surges_default_cipher_on_output():
    node = VmessNode(
        name="vmess",
        type=Protocol.VMESS,
        server="example.com",
        port=443,
        uuid="u",
        cipher="auto",
    )

    assert TargetValidationService("surge").check_node(node).supported
    output = SurgeEmitter().emit_result([node])
    assert output.errors == []
    assert "encrypt-method" not in output.content


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


def test_shadow_tls_allows_trust_tunnel_h2_but_rejects_h3_raw():
    h2 = SurgeParser().parse_result(
        "trust = trust-tunnel, example.com, 443, username=u, password=p, shadow-tls-password=s"
    )
    assert h2.issues == []
    assert h2.nodes[0].shadow_tls.enabled

    h3 = SurgeParser().parse_result(
        "trust = trust-tunnel, example.com, 443, username=u, password=p, h3=true, shadow-tls-password=s"
    )
    assert h3.nodes == []
    assert h3.issues[0].code == "parse.protocol-parameter"
