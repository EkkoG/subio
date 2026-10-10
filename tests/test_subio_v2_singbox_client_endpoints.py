import pytest

import subio_v2.adapters.singbox.endpoint as endpoint_module
import subio_v2.protocols as protocol_registry
from subio_v2.adapters.singbox.endpoint import (
    SINGBOX_ENDPOINT_CODECS,
    SINGBOX_ENDPOINT_CODECS_BY_TYPE,
    encode_endpoint,
)
from subio_v2.adapters.singbox.parser import SingBoxParser
from subio_v2.adapters.target import TargetValidationService
from subio_v2.adapters.singbox.outbound import SingBoxCodecError
from subio_v2.core.nodes import OpenConnectNode, OpenVPNNode, Protocol
from subio_v2.core.results import IssueSeverity
from subio_v2.protocols.openvpn import CODEC as OPENVPN_CODEC


def _openconnect() -> dict:
    return {
        "type": "openconnect",
        "tag": "oc",
        "detour": "direct",
        "bind_interface": "en0",
        "routing_mark": 9,
        "tcp_fast_open": True,
        "server": "https://vpn.example.com",
        "flavor": "anyconnect",
        "username": "alice",
        "password": "openconnect-secret",
        "auth_group": "staff",
        "cookie": "cookie-secret",
        "mtu": 1400,
    }


def _openvpn() -> dict:
    return {
        "type": "openvpn-client",
        "tag": "ovpn",
        "detour": "direct",
        "bind_interface": "en1",
        "routing_mark": 10,
        "tcp_multi_path": True,
        "server": "vpn.example.com",
        "server_port": 1194,
        "mode": "tls",
        "network": "tcp",
        "username": "alice",
        "password": "openvpn-secret",
        "tls": {
            "certificate": "ca-secret",
            "client_certificate": "client-cert-secret",
            "client_key": "client-key-secret",
        },
        "data_ciphers": ["AES-256-GCM", "CHACHA20-POLY1305"],
        "data_ciphers_fallback": "AES-128-GCM",
        "auth": "SHA256",
        "compression_lzo": "adaptive",
        "mtu": 1420,
    }


def _openconnect_node() -> OpenConnectNode:
    return OpenConnectNode(
        name="oc",
        server="https://vpn.example.com",
        flavor="anyconnect",
        username="alice",
        password="openconnect-secret",
        auth_group="staff",
        cookie="cookie-secret",
        mtu=1400,
    )


def _openvpn_node() -> OpenVPNNode:
    return OpenVPNNode(
        name="ovpn",
        server="vpn.example.com",
        port=1194,
        proto="tcp-client",
        data_ciphers=["AES-256-GCM", "CHACHA20-POLY1305"],
        data_ciphers_fallback="AES-128-GCM",
        auth="SHA256",
        comp_lzo="adaptive",
        ca="ca-secret",
        certificate="client-cert-secret",
        private_key="client-key-secret",
        username="alice",
        password="openvpn-secret",
        mtu=1420,
    )


def test_client_endpoint_codec_contract_matches_the_pinned_schema_subset():
    common = {
        "type",
        "tag",
        "detour",
        "bind_interface",
        "routing_mark",
        "tcp_fast_open",
        "tcp_multi_path",
    }
    assert SINGBOX_ENDPOINT_CODECS_BY_TYPE["openconnect"].allowed_keys == common | {
        "server",
        "flavor",
        "username",
        "password",
        "auth_group",
        "cookie",
        "mtu",
    }
    assert "endpoint" not in SINGBOX_ENDPOINT_CODECS_BY_TYPE["openconnect"].allowed_keys
    assert SINGBOX_ENDPOINT_CODECS_BY_TYPE["openvpn-client"].allowed_keys == common | {
        "server",
        "server_port",
        "mode",
        "network",
        "username",
        "password",
        "tls",
        "data_ciphers",
        "data_ciphers_fallback",
        "auth",
        "compression_lzo",
        "mtu",
    }
    assert endpoint_module._OPENCONNECT_FLAVORS == {
        "anyconnect",
        "gp",
        "fortinet",
        "f5",
        "pulse",
        "nc",
    }
    assert endpoint_module._OPENVPN_NETWORKS == {
        "udp",
        "udp4",
        "udp6",
        "tcp",
        "tcp4",
        "tcp6",
    }
    assert endpoint_module._OPENVPN_TLS_KEYS == {
        "certificate",
        "client_certificate",
        "client_key",
    }
    assert "AES-CBC" not in endpoint_module._OPENVPN_CANONICAL_DATA_CIPHERS
    assert {
        "BF-CBC",
        "DES-EDE3-CFB",
        "CAMELLIA-256-OFB",
        "AES-192-GCM",
        "CHACHA20-POLY1305",
        "NONE",
    } <= endpoint_module._OPENVPN_CANONICAL_DATA_CIPHERS


def test_shared_openvpn_validation_preserves_legacy_cipher_contract():
    node = _openvpn_node()
    node.data_ciphers = ["AES-CBC"]
    node.data_ciphers_fallback = "custom-cipher"

    errors = OPENVPN_CODEC.validate(node)

    assert {error.field for error in errors}.isdisjoint(
        {"data_ciphers", "data_ciphers_fallback"}
    )

    node.cipher = "BF-CBC"
    node.data_ciphers = ["BF-CBC"]
    node.data_ciphers_fallback = []
    error_fields = {error.field for error in OPENVPN_CODEC.validate(node)}
    assert error_fields >= {"cipher", "data_ciphers_fallback"}
    assert "data_ciphers" not in error_fields


@pytest.mark.parametrize(
    ("endpoint", "node_type"),
    [(_openconnect(), OpenConnectNode), (_openvpn(), OpenVPNNode)],
)
def test_client_endpoints_parse_encode_parse_round_trip(endpoint, node_type):
    parser = SingBoxParser()
    parsed = parser.parse_result({"endpoints": [endpoint]})

    assert parsed.issues == []
    assert len(parsed.nodes) == 1
    assert isinstance(parsed.nodes[0], node_type)

    encoded = encode_endpoint(parsed.nodes[0])
    reparsed = parser.parse_result({"endpoints": [encoded]})

    assert reparsed.issues == []
    assert reparsed.nodes == parsed.nodes


@pytest.mark.parametrize(
    "server",
    [
        "https://vpn.example.com:443/path",
        "https://vpn.example.com:70000",
        "https://vpn.example.com:",
        "HTTPS://vpn.example.com",
        "https://[2001:db8::1]",
        "https://vpn.example.com?",
        "https://vpn.example.com#",
        "https://vpn.example.com?#",
    ],
)
def test_openconnect_accepts_cli_valid_https_server_neighbors(server):
    endpoint = {**_openconnect(), "server": server}
    parsed = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert parsed.issues == []
    assert encode_endpoint(parsed.nodes[0])["server"] == server


@pytest.mark.parametrize(
    ("endpoint", "field"),
    [
        ({**_openconnect(), "server": "http://vpn.example.com"}, "server"),
        (
            {
                **_openconnect(),
                "server": "https://user:uri-secret@vpn.example.com",
            },
            "server",
        ),
        ({**_openconnect(), "server": "https://vpn.example.com?q=x"}, "server"),
        ({**_openconnect(), "server": "https://vpn.example.com/#x"}, "server"),
        ({**_openconnect(), "server": "https://vpn .example.com"}, "server"),
        ({**_openconnect(), "server": "https://vpn.example.com:bad"}, "server"),
        ({**_openconnect(), "server": "https://vpn.example.com:-1"}, "server"),
        ({**_openconnect(), "server": "https://vpn.example.com::443"}, "server"),
        ({**_openconnect(), "server": "https://[2001:db8::1"}, "server"),
        ({**_openvpn(), "server": "vpn .example.com"}, "server"),
        ({**_openvpn(), "server": "[2001:db8::1"}, "server"),
        ({**_openvpn(), "server": "[2001:db8::1]:bad"}, "server"),
        ({**_openvpn(), "server": "[2001:db8::1]:70000"}, "server"),
        ({**_openvpn(), "server": "[2001:db8::1]"}, "server"),
        ({**_openvpn(), "data_ciphers": ["AES-CBC"]}, "data_ciphers"),
        ({**_openvpn(), "data_ciphers": ["BOGUS"]}, "data_ciphers"),
        (
            {**_openvpn(), "data_ciphers_fallback": "AES-CBC"},
            "data_ciphers_fallback",
        ),
        (
            {**_openvpn(), "data_ciphers_fallback": "BOGUS"},
            "data_ciphers_fallback",
        ),
    ],
)
def test_client_endpoints_reject_values_rejected_by_sing_box_cli(endpoint, field):
    result = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert result.nodes == []
    assert result.issues[0].field == f"endpoints[0].{field}"
    assert "uri-secret" not in repr(result.issues)


def test_openvpn_empty_tls_client_credentials_normalize_to_omitted_values():
    endpoint = {
        **_openvpn(),
        "tls": {
            **_openvpn()["tls"],
            "client_certificate": "",
            "client_key": "",
        },
    }
    parsed = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert parsed.issues == []
    node = parsed.nodes[0]
    assert node.certificate is None
    assert node.private_key is None
    encoded = encode_endpoint(node)
    assert encoded["tls"] == {"certificate": "ca-secret"}
    assert SingBoxParser().parse_result({"endpoints": [encoded]}).nodes == [node]


def test_openvpn_accepts_cli_valid_legacy_canonical_cipher_name():
    endpoint = {
        **_openvpn(),
        "data_ciphers": ["BF-CBC"],
        "data_ciphers_fallback": "BF-CBC",
    }
    parsed = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert parsed.issues == []
    assert encode_endpoint(parsed.nodes[0])["data_ciphers"] == ["BF-CBC"]
    assert encode_endpoint(parsed.nodes[0])["data_ciphers_fallback"] == "BF-CBC"


@pytest.mark.parametrize("server", ["2001:db8::1", "vpn.example.com:bad"])
def test_openvpn_accepts_cli_valid_server_neighbors(server):
    endpoint = {**_openvpn(), "server": server}
    parsed = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert parsed.issues == []
    node = parsed.nodes[0]
    assert encode_endpoint(node)["server"] == server
    assert (
        TargetValidationService("sing-box").encode_node(node, encode_endpoint).content
        is not None
    )


def test_openconnect_protocol_is_source_bound_and_codec_registered():
    definition = protocol_registry.get_definition(Protocol.OPENCONNECT)

    assert definition is not None
    assert definition.node_class is OpenConnectNode
    assert definition.native_public is False
    assert definition.terminal_native_fields == frozenset()
    assert definition.terminal_native_excluded_fields == {
        "flavor",
        "username",
        "password",
        "auth_group",
        "cookie",
        "mtu",
    }
    assert SINGBOX_ENDPOINT_CODECS[Protocol.OPENCONNECT].singbox_type == "openconnect"
    assert SINGBOX_ENDPOINT_CODECS[Protocol.OPENVPN].singbox_type == "openvpn-client"


@pytest.mark.parametrize(
    ("endpoint", "field"),
    [
        ({**_openconnect(), "server": ["https://vpn.example.com"]}, "server"),
        ({**_openconnect(), "flavor": ["anyconnect"]}, "flavor"),
        (
            {
                **_openvpn(),
                "tls": {**_openvpn()["tls"], "certificate": ["ca-secret"]},
            },
            "tls.certificate",
        ),
        ({**_openvpn(), "network": "udp6"}, "network"),
        ({**_openvpn(), "mode": "static_key"}, "mode"),
    ],
)
def test_client_endpoint_schema_values_outside_the_ir_subset_are_rejected(
    endpoint, field
):
    result = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert result.nodes == []
    assert result.issues[0].field == f"endpoints[0].{field}"
    assert "openconnect-secret" not in repr(result.issues)
    assert "openvpn-secret" not in repr(result.issues)
    assert "client-key-secret" not in repr(result.issues)


@pytest.mark.parametrize(
    ("endpoint", "field", "marker"),
    [
        (
            {**_openconnect(), "csd": {"wrapper_path": "/tmp/DO-NOT-RUN"}},
            "csd",
            "DO-NOT-RUN",
        ),
        (
            {**_openconnect(), "token": {"secret_path": "/tmp/DO-NOT-READ"}},
            "token",
            "DO-NOT-READ",
        ),
        ({**_openvpn(), "servers": []}, "servers", "DO-NOT-READ"),
        (
            {**_openvpn(), "static_key_path": "/tmp/DO-NOT-READ"},
            "static_key_path",
            "DO-NOT-READ",
        ),
        (
            {
                **_openvpn(),
                "tls": {
                    **_openvpn()["tls"],
                    "client_key_path": "/tmp/DO-NOT-READ",
                },
            },
            "tls.client_key_path",
            "DO-NOT-READ",
        ),
    ],
)
def test_client_endpoint_unknown_runtime_and_path_fields_fail_closed(
    endpoint, field, marker
):
    result = SingBoxParser().parse_result({"endpoints": [endpoint]})

    assert result.nodes == []
    assert result.issues[0].field == f"endpoints[0].{field}"
    assert marker not in repr(result.issues)
    assert "openconnect-secret" not in repr(result.issues)
    assert "openvpn-secret" not in repr(result.issues)


@pytest.mark.parametrize(
    ("factory", "field", "value"),
    [
        (_openconnect_node, "server", ["https://vpn.example.com"]),
        (_openconnect_node, "server", "https://user:uri-secret@vpn.example.com"),
        (_openconnect_node, "server", "https://vpn.example.com?q=x"),
        (_openconnect_node, "server", "https://vpn.example.com:bad"),
        (_openconnect_node, "server", "https://[2001:db8::1"),
        (_openconnect_node, "flavor", ["anyconnect"]),
        (_openconnect_node, "password", ["openconnect-secret"]),
        (_openconnect_node, "cookie", 7),
        (_openconnect_node, "mtu", True),
        (_openvpn_node, "server", ["vpn.example.com"]),
        (_openvpn_node, "server", "vpn .example.com"),
        (_openvpn_node, "server", "[2001:db8::1"),
        (_openvpn_node, "server", "[2001:db8::1]:bad"),
        (_openvpn_node, "server", "[2001:db8::1]:70000"),
        (_openvpn_node, "server", "[2001:db8::1]"),
        (_openvpn_node, "proto", ["tcp-client"]),
        (_openvpn_node, "cipher", "AES-256-GCM"),
        (_openvpn_node, "data_ciphers", "AES-256-GCM"),
        (_openvpn_node, "data_ciphers", ["AES-CBC"]),
        (_openvpn_node, "data_ciphers", ["BOGUS"]),
        (_openvpn_node, "data_ciphers_fallback", "AES-CBC"),
        (_openvpn_node, "data_ciphers_fallback", "BOGUS"),
        (_openvpn_node, "ca", ["ca-secret"]),
        (_openvpn_node, "certificate", ["client-cert-secret"]),
        (_openvpn_node, "private_key", ["client-key-secret"]),
        (_openvpn_node, "password", ["openvpn-secret"]),
        (_openvpn_node, "certificate", ""),
        (_openvpn_node, "mtu", None),
        (_openvpn_node, "mtu", "1420"),
    ],
)
def test_client_endpoint_target_rejects_programmatic_malformed_values(
    factory, field, value
):
    node = factory()
    setattr(node, field, value)

    result = TargetValidationService("sing-box").encode_node(node, encode_endpoint)

    assert result.content is None
    assert result.supported_node is None
    assert any(
        issue.severity == IssueSeverity.ERROR and issue.field == field
        for issue in result.issues
    )
    assert "openconnect-secret" not in repr(result.issues)
    assert "cookie-secret" not in repr(result.issues)
    assert "openvpn-secret" not in repr(result.issues)
    assert "client-key-secret" not in repr(result.issues)
    assert "uri-secret" not in repr(result.issues)


def test_client_endpoint_secrets_are_hidden_from_node_and_issue_repr():
    openconnect = SingBoxParser().parse_result({"endpoints": [_openconnect()]}).nodes[0]
    openvpn = SingBoxParser().parse_result({"endpoints": [_openvpn()]}).nodes[0]

    for secret in (
        "openconnect-secret",
        "cookie-secret",
        "openvpn-secret",
        "ca-secret",
        "client-cert-secret",
        "client-key-secret",
    ):
        assert secret not in repr(openconnect)
        assert secret not in repr(openvpn)

    malformed = _openconnect_node()
    malformed.server = "https://user:uri-secret@vpn.example.com"
    assert "uri-secret" not in repr(malformed)


def test_direct_endpoint_encoder_rejects_wrong_node_type():
    with pytest.raises(SingBoxCodecError, match="Expected OpenConnectNode"):
        SINGBOX_ENDPOINT_CODECS[Protocol.OPENCONNECT].encode(_openvpn_node())
