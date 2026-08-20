"""共享值域常量和由 target codec 注册派生的 capability 查询。"""

from subio_v2.formats import normalize_format
from subio_v2.target_registry import (
    common_policy_for_target,
    protocols_for_target,
    target_platforms,
)

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

# ============== capability 聚合查询 ==============


def get_platform_capabilities(platform: str) -> dict[str, object] | None:
    """获取指定平台的能力定义"""
    import subio_v2.protocols as protocol_registry
    from subio_v2.model.nodes import Protocol

    platform = normalize_format(platform)
    common_policy = common_policy_for_target(platform)
    protocols = protocols_for_target(platform)
    if common_policy is None:
        return None
    constraints: dict[str, dict[str, object]] = {}
    for protocol_name in protocols:
        protocol = Protocol(protocol_name)
        if platform == "surge":
            from subio_v2.surge.codecs import get_surge_protocol_codec

            codec = get_surge_protocol_codec(protocol)
            if codec is None:
                raise RuntimeError(
                    f"Target protocol has no registered Surge codec: {protocol_name}"
                )
            constraints[protocol_name] = dict(codec.target_constraints)
            continue
        if platform in {"dae", "v2rayn"}:
            from subio_v2.links import get_codec

            codec = get_codec(protocol)
            if codec is None or platform not in codec.targets:
                raise RuntimeError(
                    f"Target protocol has no registered link codec: {protocol_name}"
                )
            constraints[protocol_name] = dict(
                codec.target_constraints.get(platform, {})
            )
            continue
        descriptor = protocol_registry.get(protocol)
        if descriptor is None:
            raise RuntimeError(
                f"Target protocol has no registered codec: {protocol_name}"
            )
        constraints[protocol_name] = dict(
            descriptor.constraints_for_target(platform)
        )
    return {
        "protocols": protocols,
        "global_features": common_policy.as_feature_map(),
        **constraints,
    }


def all_platform_capabilities() -> dict[str, dict[str, object]]:
    return {
        platform: get_platform_capabilities(platform)
        for platform in target_platforms()
    }
