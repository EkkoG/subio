"""
Platform Capabilities Definitions

集中定义各平台对代理协议的支持情况：
- 支持的协议类型
- 每种协议支持的加密方法
- 每种协议支持的传输方式
- 其他特性支持
"""

from typing import Dict, Any, Optional

from subio_v2.platforms import normalize_platform
from subio_v2.surge.codecs import SURGE_NODE_PROTOCOLS

# ============== 通用常量 ==============

# Shadowsocks 加密方法
SS_CIPHERS_BASIC = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
}

SS_CIPHERS_EXTENDED = SS_CIPHERS_BASIC | {
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
    "xchacha20-ietf-poly1305",
}

SS_CIPHERS_2022 = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}

SS_CIPHERS_STASH = SS_CIPHERS_EXTENDED | {
    "aes-192-gcm",
    "chacha20",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
}

# Surge supports the two AES-based 2022 methods plus its own legacy set.
SS_CIPHERS_SURGE = {
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

# VMess 加密方法
VMESS_CIPHERS = {
    "auto",
    "aes-128-gcm",
    "chacha20-poly1305",
    "none",
    "zero",
}

VMESS_CIPHERS_STASH = VMESS_CIPHERS - {"zero"}

# 传输方式
TRANSPORT_TCP = "tcp"
TRANSPORT_WS = "ws"
TRANSPORT_H2 = "h2"
TRANSPORT_GRPC = "grpc"
TRANSPORT_HTTP = "http"
TRANSPORT_XHTTP = "xhttp"

# ============== 平台能力定义 ==============

PLATFORM_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    # ============== Surge ==============
    "surge": {
        "protocols": set(SURGE_NODE_PROTOCOLS),
        "shadowsocks": {
            "ciphers": SS_CIPHERS_SURGE,
            "plugins": {"obfs"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS},
        },
        "http": {
            "features": {"tls", "h2-connect", "connect-udp"},
        },
        "socks5": {
            "features": {"tls"},  # socks5-tls
        },
        "snell": {
            "versions": {1, 2, 3, 4, 5, 6},
            "reuse_versions": {4, 5, 6},
            "obfs_modes": {"http", "tls"},
            "obfs_modes_by_version": {
                1: {"http", "tls"},
                2: {"http", "tls"},
                3: {"http", "tls"},
                4: {"http"},
                5: {"http"},
                6: set(),
            },
        },
        "tuic": {
            "versions": {4, 5},
        },
        "hysteria2": {
            "features": {"obfs"},
            "obfs_modes": {"salamander", "gecko"},
        },
        "ssh": {
            "auth_methods": {"password", "private_key"},
        },
        "anytls": {},
        "wireguard": {},
        "tailscale": {},
        "masque": {},
        "trusttunnel": {},
        "direct": {},
        "reject": {
            "modes": {"reject", "reject-drop", "reject-no-drop", "reject-tinygif"},
        },
        # 全局特性
        "global_features": {
            "tfo": True,
            "mptcp": False,
            "dialer_proxy": True,
        },
    },
    # ============== Mihomo ==============
    "mihomo": {
        "protocols": {
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
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_EXTENDED | SS_CIPHERS_2022,
            "plugins": {"obfs", "v2ray-plugin", "shadow-tls", "restls"},
            "features": {"smux"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
            },
            "features": {"reality", "smux"},
        },
        "vless": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
                TRANSPORT_XHTTP,
            },
            "features": {"reality", "smux"},
            "flows": {"xtls-rprx-vision"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
            "features": {"reality", "smux"},
        },
        "http": {
            "features": {"tls"},
        },
        "socks5": {
            "features": {"tls"},
        },
        "hysteria": {
            "features": {"obfs"},
        },
        "hysteria2": {
            "features": {"obfs"},
        },
        "tuic": {
            "versions": {4, 5},
        },
        "snell": {
            "versions": {1, 2, 3, 4, 5},
            "reuse_versions": {4, 5},
            "obfs_modes": {"http", "tls"},
        },
        "shadowsocksr": {},
        "mieru": {
            "transports": {"TCP", "UDP"},
            "multiplexing": {
                "MULTIPLEXING_DEFAULT",
                "MULTIPLEXING_OFF",
                "MULTIPLEXING_LOW",
                "MULTIPLEXING_MIDDLE",
                "MULTIPLEXING_HIGH",
            },
            "handshake_modes": {
                "HANDSHAKE_DEFAULT",
                "HANDSHAKE_STANDARD",
                "HANDSHAKE_NO_WAIT",
            },
            "features": {"smux", "traffic-pattern"},
        },
        "gost-relay": {},
        "rematch": {},
        "shadowquic": {},
        "sudoku": {},
        "masque": {},
        "trusttunnel": {},
        "openvpn": {},
        "tailscale": {},
        "direct": {},
        "reject": {"modes": {"reject"}, "features": {"smux"}},
        "dns": {"features": {"smux"}},
        "wireguard": {},
        "ssh": {
            "auth_methods": {"password", "private_key"},
        },
        "anytls": {},
        # 全局特性
        "global_features": {
            "tfo": True,
            "mptcp": True,
            "dialer_proxy": True,
        },
    },
    # ============== Clash (原版) ==============
    "clash": {
        "protocols": {
            "shadowsocks",
            "vmess",
            "trojan",
            "http",
            "socks5",
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_EXTENDED,
            "plugins": {"obfs", "v2ray-plugin"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_H2, TRANSPORT_HTTP},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS},
        },
        "http": {
            "features": {"tls"},
        },
        "socks5": {
            "features": {"tls"},
        },
        "global_features": {
            "tfo": False,
            "mptcp": False,
            "dialer_proxy": False,
        },
    },
    # ============== Stash ==============
    "stash": {
        "protocols": {
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
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_STASH,
            "plugins": {"obfs", "v2ray-plugin", "shadow-tls"},
        },
        "shadowsocksr": {
            "ciphers": SS_CIPHERS_STASH,
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS_STASH,
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
            },
        },
        "vless": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
                TRANSPORT_XHTTP,
            },
            "features": {"reality"},
            "flows": {
                "xtls-rprx-origin",
                "xtls-rprx-direct",
                "xtls-rprx-splice",
                "xtls-rprx-vision",
            },
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC},
        },
        "http": {
            "features": {"tls"},
        },
        "socks5": {
            "features": {"tls"},
        },
        "snell": {
            "versions": {3, 4},
            "reuse_versions": {4},
            "obfs_modes": {"http", "tls"},
        },
        "wireguard": {},
        "hysteria": {
            "features": {"obfs"},
        },
        "hysteria2": {
            "features": {"obfs"},
            "obfs_modes": {"salamander", "gecko"},
        },
        "tuic": {
            "versions": {4, 5},
        },
        "ssh": {
            "auth_methods": {"password", "private_key"},
        },
        "anytls": {},
        "direct": {},
        "mieru": {
            "transports": {"TCP"},
            "multiplexing": set(),
            "handshake_modes": set(),
        },
        "juicity": {},
        "tailscale": {},
        "masque": {},
        "trusttunnel": {},
        "global_features": {
            "tfo": True,
            "mptcp": False,
            "dialer_proxy": True,
        },
    },
    # ============== dae ==============
    "dae": {
        "protocols": {
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "http",
            "socks5",
            "hysteria2",
            "tuic",
            "anytls",
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_EXTENDED | SS_CIPHERS_2022,
            "plugins": {"obfs", "shadow-tls"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
        },
        "vless": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
            "features": {"reality"},
            "flows": {"xtls-rprx-vision"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC},
        },
        "http": {
            "features": {"tls"},
        },
        "socks5": {},
        "hysteria2": {
            "features": {"obfs"},
        },
        "tuic": {
            "versions": {5},
        },
        "anytls": {},
        # 全局特性
        "global_features": {
            "tfo": False,
            "mptcp": True,
            "dialer_proxy": True,
        },
    },
    # ============== v2rayN ==============
    "v2rayn": {
        "protocols": {
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "socks5",
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_EXTENDED | SS_CIPHERS_2022,
            "plugins": {"obfs", "v2ray-plugin"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
            },
        },
        "vless": {
            "transports": {
                TRANSPORT_TCP,
                TRANSPORT_WS,
                TRANSPORT_GRPC,
                TRANSPORT_H2,
                TRANSPORT_HTTP,
            },
            "features": {"reality"},
            "flows": {"xtls-rprx-vision"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
        },
        "socks5": {},
        "global_features": {
            "tfo": False,
            "mptcp": False,
            "dialer_proxy": False,
        },
    },
}

# 协议类型到内部名称的映射
PROTOCOL_NAME_MAP = {
    "ss": "shadowsocks",
    "shadowsocks": "shadowsocks",
    "ssr": "shadowsocksr",
    "shadowsocksr": "shadowsocksr",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "http": "http",
    "https": "http",
    "socks5": "socks5",
    "socks5-tls": "socks5",
    "snell": "snell",
    "tuic": "tuic",
    "tuic-v5": "tuic",
    "hysteria": "hysteria",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "mieru": "mieru",
    "juicity": "juicity",
    "gost-relay": "gost-relay",
    "rematch": "rematch",
    "shadowquic": "shadowquic",
    "sudoku": "sudoku",
    "masque": "masque",
    "trusttunnel": "trusttunnel",
    "openvpn": "openvpn",
    "tailscale": "tailscale",
    "direct": "direct",
    "reject": "reject",
    "dns": "dns",
    "wireguard": "wireguard",
    "wg": "wireguard",
    "ssh": "ssh",
    "anytls": "anytls",
}


def get_platform_capabilities(platform: str) -> Optional[Dict[str, Any]]:
    """获取指定平台的能力定义"""
    return PLATFORM_CAPABILITIES.get(normalize_platform(platform))


def normalize_protocol_name(protocol: str) -> str:
    """标准化协议名称"""
    return PROTOCOL_NAME_MAP.get(protocol.lower(), protocol.lower())


def is_protocol_supported(platform: str, protocol: str) -> bool:
    """检查平台是否支持指定协议"""
    caps = get_platform_capabilities(platform)
    if not caps:
        return False
    normalized = normalize_protocol_name(protocol)
    return normalized in caps.get("protocols", set())


def get_protocol_capabilities(platform: str, protocol: str) -> Optional[Dict[str, Any]]:
    """获取平台对指定协议的能力定义"""
    caps = get_platform_capabilities(platform)
    if not caps:
        return None
    normalized = normalize_protocol_name(protocol)
    return caps.get(normalized)
