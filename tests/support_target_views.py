"""Test-only target views derived from executable codec registries."""

from __future__ import annotations

import subio_v2.protocols as protocol_registry
from subio_v2.formats import all_formats, common_policy_for_format, normalize_format
from subio_v2.links import all_codecs as all_link_codecs
from subio_v2.surge.codecs import SURGE_PROTOCOL_CODECS


def _protocol_codecs(target: str):
    if target in {"mihomo", "clash", "stash"}:
        return {
            codec.protocol: codec
            for codec in protocol_registry.all()
            if codec.supports_dialect(target)
        }
    if target == "surge":
        return dict(SURGE_PROTOCOL_CODECS)
    return {
        codec.protocol: codec
        for codec in all_link_codecs()
        if target in codec.targets
    }


def all_platform_capabilities() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for spec in all_formats():
        target = spec.name
        policy = common_policy_for_format(target)
        if policy is None:
            continue
        codecs = _protocol_codecs(target)
        view: dict[str, object] = {
            "protocols": frozenset(protocol.value for protocol in codecs),
            "global_features": policy.as_feature_map(),
        }
        for protocol, codec in codecs.items():
            if target in {"mihomo", "clash", "stash"}:
                constraints = codec.target_constraints
            elif target == "surge":
                constraints = codec.target_constraints
            else:
                constraints = codec.target_constraints.get(target, {})
            view[protocol.value] = dict(constraints)
        result[target] = view
    result["clash-meta"] = result["mihomo"]
    return result


def protocols_for_target(target: str) -> frozenset[str]:
    return all_platform_capabilities().get(normalize_format(target), {}).get(
        "protocols", frozenset()
    )
