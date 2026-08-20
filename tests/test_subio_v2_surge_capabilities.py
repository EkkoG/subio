from tests.support_target_views import all_platform_capabilities
from subio_v2.adapters.target import TargetValidationService as NodeConversionService

PLATFORM_CAPABILITIES = all_platform_capabilities()
from subio_v2.core.nodes import (
    Hysteria2Node,
    Protocol,
    ShadowsocksNode,
    SnellNode,
    TUICNode,
)

SURGE_SHADOWSOCKS_CIPHERS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
    "none",
}


def test_surge_shadowsocks_ciphers_match_official_baseline():
    capabilities = PLATFORM_CAPABILITIES["surge"]["shadowsocks"]

    assert capabilities["ciphers"] == SURGE_SHADOWSOCKS_CIPHERS
    assert "2022-blake3-chacha20-poly1305" not in capabilities["ciphers"]


def test_surge_checker_accepts_official_ciphers_and_rejects_2022_chacha():
    checker = NodeConversionService("surge")

    for cipher in SURGE_SHADOWSOCKS_CIPHERS:
        if cipher == "2022-blake3-aes-128-gcm":
            password = "MDEyMzQ1Njc4OWFiY2RlZg=="
        elif cipher == "2022-blake3-aes-256-gcm":
            password = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
        else:
            password = "password"
        node = ShadowsocksNode(
            name=cipher,
            type=Protocol.SHADOWSOCKS,
            server="example.com",
            port=8388,
            cipher=cipher,
            password=password,
        )
        assert checker.check_node(node).supported, cipher

    unsupported = ShadowsocksNode(
        name="unsupported-2022-chacha",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="2022-blake3-chacha20-poly1305",
        password="password",
    )
    assert not checker.check_node(unsupported).supported


def test_surge_snell_versions_match_official_baseline():
    assert PLATFORM_CAPABILITIES["surge"]["snell"]["versions"] == set(range(1, 7))

    checker = NodeConversionService("surge")
    for version in range(1, 7):
        node = SnellNode(
            name=f"snell-v{version}",
            type=Protocol.SNELL,
            server="example.com",
            port=443,
            psk="password",
            version=version,
        )
        assert checker.check_node(node).supported, version


def test_surge_snell_obfs_is_checked_by_protocol_version():
    checker = NodeConversionService("surge")

    def supported(version, obfs):
        node = SnellNode(
            name=f"snell-v{version}-{obfs}",
            type=Protocol.SNELL,
            server="example.com",
            port=443,
            psk="password",
            version=version,
            obfs=obfs,
        )
        return checker.check_node(node).supported

    assert supported(1, "tls")
    assert supported(3, "http")
    assert supported(4, "http")
    assert not supported(4, "tls")
    assert not supported(6, "http")


def test_surge_declares_underlying_proxy_and_hysteria2_obfs():
    capabilities = PLATFORM_CAPABILITIES["surge"]

    assert capabilities["global_features"]["dialer_proxy"] is True
    assert "obfs" in capabilities["hysteria2"]["features"]
    assert capabilities["hysteria2"]["obfs_modes"] == {"salamander", "gecko"}

    node = Hysteria2Node(
        name="hy2-obfs",
        type=Protocol.HYSTERIA2,
        server="example.com",
        port=443,
        password="password",
        obfs="salamander",
        obfs_password="secret",
        dialer_proxy="base",
    )
    result = NodeConversionService("surge").check_node(node)
    assert result.supported
    assert not {"obfs", "dialer_proxy"} & {warning.field for warning in result.warnings}


def test_surge_shadowsocks_conditional_password_rules():
    checker = NodeConversionService("surge")
    none_cipher = ShadowsocksNode(
        name="none",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="none",
        password="",
    )
    valid_2022 = ShadowsocksNode(
        name="2022",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="2022-blake3-aes-128-gcm",
        password="MDEyMzQ1Njc4OWFiY2RlZg==",
    )
    invalid_2022 = ShadowsocksNode(
        name="bad-2022",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="2022-blake3-aes-256-gcm",
        password="short",
    )

    assert checker.check_node(none_cipher).supported
    assert checker.check_node(valid_2022).supported
    assert not checker.check_node(invalid_2022).supported


def test_surge_port_hopping_rejects_underlying_proxy():
    checker = NodeConversionService("surge")
    for node in (
        TUICNode(
            name="tuic",
            type=Protocol.TUIC,
            server="example.com",
            port=443,
            version=5,
            uuid="u",
            password="p",
            ports="443-445",
            dialer_proxy="base",
        ),
        Hysteria2Node(
            name="hy2",
            type=Protocol.HYSTERIA2,
            server="example.com",
            port=443,
            password="p",
            ports="443-445",
            dialer_proxy="base",
        ),
    ):
        result = checker.check_node(node)
        assert not result.supported
        assert "ports" in {warning.field for warning in result.warnings}
