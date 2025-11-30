"""
Platform Capabilities Definitions

集中定义各平台对代理协议的支持情况：
- 支持的协议类型
- 每种协议支持的加密方法
- 每种协议支持的传输方式
- 其他特性支持
"""

from typing import Dict, Any, Optional

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

# VMess 加密方法
VMESS_CIPHERS = {
    "auto",
    "aes-128-gcm",
    "chacha20-poly1305",
    "none",
    "zero",
}

# 传输方式
TRANSPORT_TCP = "tcp"
TRANSPORT_WS = "ws"
TRANSPORT_H2 = "h2"
TRANSPORT_GRPC = "grpc"
TRANSPORT_HTTP = "http"

# ============== 平台能力定义 ==============

PLATFORM_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    # ============== Surge ==============
    "surge": {
        "protocols": {
            "shadowsocks",
            "vmess",
            "trojan",
            "http",
            "socks5",
            "snell",
            "tuic",
            "hysteria2",
            "ssh",
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_BASIC | SS_CIPHERS_2022,
            "transports": {TRANSPORT_TCP},
            "plugins": {"obfs"},
            "features": {"udp"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS},
            "features": {"udp", "tls"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS},
            "features": {"udp", "tls"},
        },
        "http": {
            "features": {"tls"},  # https
        },
        "socks5": {
            "features": {"tls", "udp"},  # socks5-tls
        },
        "snell": {
            "versions": {3, 4, 5},
            "obfs_modes": {"http", "tls"},
        },
        "tuic": {
            "versions": {4, 5},
            "features": {"udp"},
        },
        "hysteria2": {
            "features": {"udp"},
        },
        "ssh": {
            "auth_methods": {"password", "private_key"},
        },
        # 全局特性
        "global_features": {
            "udp_relay": True,
            "tfo": True,
            "mptcp": False,
            "dialer_proxy": False,
        },
    },
    # ============== Clash Meta ==============
    "clash-meta": {
        "protocols": {
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "http",
            "socks5",
            "hysteria2",
            "tuic",
            "wireguard",
            "ssh",
            "anytls",
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_EXTENDED | SS_CIPHERS_2022,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
            "plugins": {"obfs", "v2ray-plugin", "shadow-tls", "restls"},
            "features": {"udp", "smux"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2, TRANSPORT_HTTP},
            "features": {"udp", "tls", "reality", "smux"},
        },
        "vless": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2, TRANSPORT_HTTP},
            "features": {"udp", "tls", "reality", "xtls", "smux"},
            "flows": {"xtls-rprx-vision"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
            "features": {"udp", "tls", "reality", "smux"},
        },
        "http": {
            "features": {"tls"},
        },
        "socks5": {
            "features": {"tls", "udp"},
        },
        "hysteria2": {
            "features": {"udp", "obfs"},
        },
        "tuic": {
            "versions": {5},
            "features": {"udp"},
        },
        "wireguard": {
            "features": {"udp"},
        },
        "ssh": {
            "auth_methods": {"password", "private_key"},
        },
        "anytls": {
            "features": {"tls"},
        },
        # 全局特性
        "global_features": {
            "udp_relay": True,
            "tfo": True,
            "mptcp": True,
            "dialer_proxy": True,
            "smux": True,
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
            "transports": {TRANSPORT_TCP},
            "plugins": {"obfs", "v2ray-plugin"},
            "features": {"udp"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_H2, TRANSPORT_HTTP},
            "features": {"udp", "tls"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS},
            "features": {"udp", "tls"},
        },
        "http": {
            "features": {"tls"},
        },
        "socks5": {
            "features": {"tls", "udp"},
        },
        "global_features": {
            "udp_relay": True,
            "tfo": False,
            "mptcp": False,
            "dialer_proxy": False,
        },
    },
    # ============== Stash ==============
    "stash": {
        "protocols": {
            "shadowsocks",
            "vmess",
            "trojan",
            "http",
            "socks5",
            "snell",
            "wireguard",
            "hysteria2",
        },
        "shadowsocks": {
            "ciphers": SS_CIPHERS_EXTENDED | SS_CIPHERS_2022,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS},
            "plugins": {"obfs", "v2ray-plugin", "shadow-tls"},
            "features": {"udp"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
            "features": {"udp", "tls"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC},
            "features": {"udp", "tls"},
        },
        "http": {
            "features": {"tls"},
        },
        "socks5": {
            "features": {"tls", "udp"},
        },
        "snell": {
            "versions": {3, 4},
            "obfs_modes": {"http", "tls"},
        },
        "wireguard": {
            "features": {"udp"},
        },
        "hysteria2": {
            "features": {"udp"},
        },
        "global_features": {
            "udp_relay": True,
            "tfo": True,
            "mptcp": False,
            "dialer_proxy": False,
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
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
            "plugins": {"obfs", "v2ray-plugin"},
            "features": {"udp"},
        },
        "vmess": {
            "ciphers": VMESS_CIPHERS,
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2, TRANSPORT_HTTP},
            "features": {"udp", "tls"},
        },
        "vless": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2, TRANSPORT_HTTP},
            "features": {"udp", "tls", "reality", "xtls"},
            "flows": {"xtls-rprx-vision"},
        },
        "trojan": {
            "transports": {TRANSPORT_TCP, TRANSPORT_WS, TRANSPORT_GRPC, TRANSPORT_H2},
            "features": {"udp", "tls"},
        },
        "socks5": {
            "features": {"udp"},
        },
        "global_features": {
            "udp_relay": True,
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
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "wireguard": "wireguard",
    "wg": "wireguard",
    "ssh": "ssh",
    "anytls": "anytls",
}


def get_platform_capabilities(platform: str) -> Optional[Dict[str, Any]]:
    """获取指定平台的能力定义"""
    return PLATFORM_CAPABILITIES.get(platform)


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

