from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from subio_v2.core.nodes import (
    Node,
    Protocol,
)
from subio_v2.core.results import IssueDraft

DEFAULT_SURGE_TARGET = "latest"


class SurgePolicyKind(StrEnum):
    NODE = "node"
    DOCUMENT = "document"


class SurgeUdpBehavior(StrEnum):
    EXPLICIT = "explicit"
    AUTOMATIC = "automatic"
    VERSIONED = "versioned"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class SurgeCodecSpec:
    keyword: str
    check: Callable[[Node, Mapping[str, Any]], list[IssueDraft]]
    protocol: Protocol | None
    policy_kind: SurgePolicyKind
    udp_behavior: SurgeUdpBehavior
    precheck: Callable[[Node], list[IssueDraft]] = lambda node: []
    consumed_parameters: frozenset[str] = frozenset()
    emitted_parameters: frozenset[str] = frozenset()
    normalized_parameters: tuple[tuple[str, str], ...] = ()
    multi_value_parameters: frozenset[str] = frozenset()
    target_constraints: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({})
    )
    parser: Callable[[Any], Any] | None = None
    emitter: Callable[[Any, dict[int, str]], list[str]] | None = None

    @property
    def parameter_path_sources(self) -> frozenset[str]:
        return self.emitted_parameters | frozenset(
            source for source, _ in self.normalized_parameters
        )


def _spec(
    keyword: str,
    *,
    protocol: Protocol | None,
    check: Callable[[Node, Mapping[str, Any]], list[IssueDraft]] = lambda node,
    constraints: [],
    precheck: Callable[[Node], list[IssueDraft]] = lambda node: [],
    kind: SurgePolicyKind = SurgePolicyKind.NODE,
    udp: SurgeUdpBehavior,
    consumed: tuple[str, ...] = (),
    emitted: tuple[str, ...] | None = None,
    normalized: tuple[tuple[str, str], ...] = (),
    multi: tuple[str, ...] = (),
    constraints: Mapping[str, Any] | None = None,
    parser: Callable[[Any], Any] | None = None,
    emitter: Callable[[Any, dict[int, str]], list[str]] | None = None,
) -> SurgeCodecSpec:
    return SurgeCodecSpec(
        keyword=keyword,
        check=check,
        precheck=precheck,
        protocol=protocol,
        policy_kind=kind,
        udp_behavior=udp,
        consumed_parameters=frozenset(consumed),
        emitted_parameters=frozenset(consumed if emitted is None else emitted),
        normalized_parameters=normalized,
        multi_value_parameters=frozenset(multi),
        target_constraints=MappingProxyType(dict(constraints or {})),
        parser=parser,
        emitter=emitter,
    )


SURGE_COMMON_PARAMETERS = frozenset(
    {
        "interface",
        "allow-other-interface",
        "dns-follow-interface",
        "no-error-alert",
        "ip-version",
        "hybrid",
        "tfo",
        "tos",
        "ecn",
        "block-quic",
        "test-url",
        "test-timeout",
        "test-udp",
        "underlying-proxy",
        "skip-cert-verify",
        "sni",
        "server-cert-verify-name",
        "server-cert-fingerprint-sha256",
        "alpn",
        "client-cert",
        "shadow-tls-password",
        "shadow-tls-sni",
        "shadow-tls-version",
    }
)


SURGE_COMMON_PARAMETER_PATHS = SURGE_COMMON_PARAMETERS
