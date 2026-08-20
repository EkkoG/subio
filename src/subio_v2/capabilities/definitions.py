"""共享值域常量和由 target codec 注册派生的 capability 查询。"""

from subio_v2.formats import normalize_format
from subio_v2.target_registry import (
    common_policy_for_target,
    protocols_for_target,
    target_platforms,
)

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
