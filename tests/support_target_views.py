"""Test-only target views derived from executable codec registries."""

from __future__ import annotations

from subio_v2.adapters.catalog import all_formats, get_target, normalize_format


def all_platform_capabilities() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for spec in all_formats():
        target = spec.name
        policy = spec.common_policy
        if policy is None:
            continue
        codecs = get_target(target).codecs
        view: dict[str, object] = {
            "protocols": frozenset(protocol.value for protocol in codecs),
            "global_features": policy.as_feature_map(),
        }
        for protocol, codec in codecs.items():
            constraints = codec.target_constraints
            view[protocol.value] = dict(constraints)
        result[target] = view
    result["clash-meta"] = result["mihomo"]
    return result


def protocols_for_target(target: str) -> frozenset[str]:
    return (
        all_platform_capabilities()
        .get(normalize_format(target), {})
        .get("protocols", frozenset())
    )
