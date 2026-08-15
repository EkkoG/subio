from __future__ import annotations

import copy
from typing import Any

from subio_v2.capabilities.definitions import get_platform_capabilities
from subio_v2.dialect import DialectContext
from subio_v2.model.nodes import Node


def pre_descriptor_normalize(
    data: dict[str, Any], context: DialectContext
) -> dict[str, Any]:
    """Hook for source-dialect key normalization before shared descriptors."""
    if context.dialect == "stash":
        from subio_v2.clash.stash import normalize_stash_proxy

        return normalize_stash_proxy(data)
    return copy.deepcopy(data)


def post_descriptor_emit(
    data: dict[str, Any],
    node: Node,
    context: DialectContext,
    platform: str,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Apply target capability gates and report modeled fields that were dropped."""
    output = data
    dropped: set[str] = set()
    capabilities = get_platform_capabilities(platform) or {}
    global_features = capabilities.get("global_features", {})

    for semantic_field, output_key, capability in (
        ("tfo", "tfo", "tfo"),
        ("mptcp", "mptcp", "mptcp"),
        ("dialer_proxy", "dialer-proxy", "dialer_proxy"),
    ):
        if output_key in output and not global_features.get(capability, False):
            output.pop(output_key, None)
            dropped.add(semantic_field)

    protocol_caps = capabilities.get(node.type.value, {})
    if "smux" in output and "smux" not in protocol_caps.get("features", set()):
        output.pop("smux", None)
        dropped.add("smux")

    # ECH is currently a Mihomo semantic. Stash gets its own field map in stage 8.
    if "ech-opts" in output and context.dialect != "mihomo":
        output.pop("ech-opts", None)
        dropped.add("tls.ech_opts")

    transport = getattr(node, "transport", None)
    if (
        transport is not None
        and getattr(transport, "extra", None)
        and getattr(transport, "extra_context", None) is not None
        and transport.extra_context.dialect != context.dialect
    ):
        for block, fields in transport.extra.items():
            payload = output.get(block)
            if not isinstance(payload, dict):
                continue
            for key in fields:
                if key in payload:
                    payload.pop(key)
            if not payload:
                output.pop(block, None)

    return output, tuple(sorted(dropped))
