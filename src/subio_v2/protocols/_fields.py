from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from subio_v2.adapters.clash_family.fields import (
    emit_smux,
    emit_tls,
    emit_transport,
    parse_smux,
    parse_tls,
    parse_transport,
)
from subio_v2.core.nodes import Node


class EmitPolicy(StrEnum):
    ALWAYS = "always"
    TRUTHY = "truthy"
    NOT_NONE = "not-none"


FieldParser = Callable[[Mapping[str, Any]], dict[str, Any]]
FieldEmitter = Callable[[MutableMapping[str, Any], Node], None]


@dataclass(frozen=True)
class ClashFieldSpec:
    """One declarative unit of Clash parse/emit behavior."""

    consumed_keys: frozenset[str]
    node_attrs: frozenset[str]
    required_attrs: frozenset[str]
    parse_kwargs: FieldParser
    emit_into: FieldEmitter


def scalar_field(
    key: str,
    attr: str | None = None,
    *,
    aliases: tuple[str, ...] = (),
    default: Any = None,
    decode: Callable[[Any], Any] | None = None,
    encode: Callable[[Any], Any] | None = None,
    emit_policy: EmitPolicy = EmitPolicy.NOT_NONE,
    emit_if: Callable[[Node, Any], bool] | None = None,
    required: bool = False,
) -> ClashFieldSpec:
    attr = attr or key.replace("-", "_")
    keys = (key, *aliases)

    def parse_kwargs(data: Mapping[str, Any]) -> dict[str, Any]:
        value = default
        for candidate in keys:
            if candidate in data:
                value = data[candidate]
                break
        if decode is not None:
            value = decode(value)
        return {attr: copy.deepcopy(value)}

    def emit_into(out: MutableMapping[str, Any], node: Node) -> None:
        value = getattr(node, attr)
        if emit_if is not None and not emit_if(node, value):
            return
        if emit_policy == EmitPolicy.TRUTHY and not value:
            return
        if emit_policy == EmitPolicy.NOT_NONE and value is None:
            return
        if encode is not None:
            value = encode(value)
        out[key] = copy.deepcopy(value)

    return ClashFieldSpec(
        consumed_keys=frozenset(keys),
        node_attrs=frozenset({attr}),
        required_attrs=frozenset({attr}) if required else frozenset(),
        parse_kwargs=parse_kwargs,
        emit_into=emit_into,
    )


def field_group(
    *,
    consumed_keys: tuple[str, ...],
    node_attrs: tuple[str, ...],
    parse_kwargs: FieldParser,
    emit_into: FieldEmitter,
    required_attrs: tuple[str, ...] = (),
) -> ClashFieldSpec:
    return ClashFieldSpec(
        consumed_keys=frozenset(consumed_keys),
        node_attrs=frozenset(node_attrs),
        required_attrs=frozenset(required_attrs),
        parse_kwargs=parse_kwargs,
        emit_into=emit_into,
    )


TLS_KEYS = (
    "tls",
    "servername",
    "sni",
    "alpn",
    "skip-cert-verify",
    "fingerprint",
    "client-fingerprint",
    "name-cert-verify",
    "reality-opts",
    "ech-opts",
    "certificate",
    "private-key",
)

TRANSPORT_KEYS = (
    "network",
    "ws-opts",
    "h2-opts",
    "http-opts",
    "grpc-opts",
    "xhttp-opts",
)


def tls_group(
    *,
    consumed_keys: tuple[str, ...] = TLS_KEYS,
    default_enabled: bool = False,
    force_enabled: bool = False,
) -> ClashFieldSpec:
    def parse_kwargs(data: Mapping[str, Any]) -> dict[str, Any]:
        tls = parse_tls(dict(data), default_enabled=default_enabled)
        if force_enabled:
            tls.enabled = True
        return {"tls": tls}

    def emit_into(out: MutableMapping[str, Any], node: Node) -> None:
        emit_tls(out, getattr(node, "tls"))

    return field_group(
        consumed_keys=consumed_keys,
        node_attrs=("tls",),
        parse_kwargs=parse_kwargs,
        emit_into=emit_into,
    )


def transport_group(
    *, consumed_keys: tuple[str, ...] = TRANSPORT_KEYS
) -> ClashFieldSpec:
    return field_group(
        consumed_keys=consumed_keys,
        node_attrs=("transport",),
        parse_kwargs=lambda data: {"transport": parse_transport(dict(data))},
        emit_into=lambda out, node: emit_transport(out, getattr(node, "transport")),
    )


def smux_group() -> ClashFieldSpec:
    return field_group(
        consumed_keys=("smux",),
        node_attrs=("smux",),
        parse_kwargs=lambda data: {"smux": parse_smux(dict(data))},
        emit_into=lambda out, node: emit_smux(out, getattr(node, "smux")),
    )
