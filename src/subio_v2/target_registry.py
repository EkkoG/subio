from subio_v2.platforms import normalize_platform

_TARGET_PROTOCOLS: dict[str, frozenset[str]] = {
    "mihomo": frozenset(
        {
            "shadowsocks",
            "shadowsocksr",
            "vmess",
            "vless",
            "trojan",
            "http",
            "socks5",
            "hysteria",
            "hysteria2",
            "tuic",
            "gost-relay",
            "snell",
            "wireguard",
            "ssh",
            "anytls",
            "mieru",
            "rematch",
            "sudoku",
            "masque",
            "trusttunnel",
            "openvpn",
            "tailscale",
            "shadowquic",
            "direct",
            "reject",
            "dns",
        }
    ),
    "clash": frozenset({"shadowsocks", "vmess", "trojan", "http", "socks5"}),
    "stash": frozenset(
        {
            "shadowsocks",
            "shadowsocksr",
            "vmess",
            "vless",
            "trojan",
            "http",
            "socks5",
            "snell",
            "wireguard",
            "hysteria",
            "hysteria2",
            "tuic",
            "ssh",
            "anytls",
            "direct",
            "mieru",
            "juicity",
            "tailscale",
            "masque",
            "trusttunnel",
        }
    ),
    "surge": frozenset(
        {
            "shadowsocks",
            "vmess",
            "trojan",
            "http",
            "socks5",
            "snell",
            "tuic",
            "hysteria2",
            "ssh",
            "anytls",
            "wireguard",
            "tailscale",
            "masque",
            "trusttunnel",
            "direct",
            "reject",
        }
    ),
    "dae": frozenset(
        {
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "http",
            "socks5",
            "hysteria2",
            "tuic",
            "anytls",
        }
    ),
    "v2rayn": frozenset(
        {"shadowsocks", "vmess", "vless", "trojan", "socks5"}
    ),
}


def protocols_for_target(platform: str) -> frozenset[str]:
    return _TARGET_PROTOCOLS.get(normalize_platform(platform), frozenset())


def target_platforms() -> frozenset[str]:
    return frozenset(_TARGET_PROTOCOLS)
