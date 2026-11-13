from __future__ import annotations

import copy
from collections.abc import Mapping, MutableMapping
from typing import Any

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    field_group,
    scalar_field,
    smux_group,
)
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import (
    Node,
    Protocol,
    SudokuHTTPMaskSettings,
    SudokuNode,
)
from subio_v2.protocols.sudoku import SPEC

_HTTPMASK_KEYS = {"disable", "mode", "tls", "host", "path-root", "multiplex"}


def _parse_httpmask(data: Mapping[str, Any]) -> dict[str, object]:
    raw = data.get("httpmask")
    if raw is None:
        return {"httpmask": None}
    if not isinstance(raw, Mapping):
        return {"httpmask": raw}
    return {
        "httpmask": SudokuHTTPMaskSettings(
            disable=raw.get("disable"),
            mode=raw.get("mode"),
            tls=raw.get("tls"),
            host=raw.get("host"),
            path_root=raw.get("path-root"),
            multiplex=raw.get("multiplex"),
        )
    }


def _emit_httpmask(out: MutableMapping[str, Any], node: Node) -> None:
    assert isinstance(node, SudokuNode)
    settings = node.httpmask
    if settings is None:
        return
    if not isinstance(settings, SudokuHTTPMaskSettings):
        out["httpmask"] = settings
        return
    payload: dict[str, Any] = {}
    for attr, key in (
        ("disable", "disable"),
        ("mode", "mode"),
        ("tls", "tls"),
        ("host", "host"),
        ("path_root", "path-root"),
        ("multiplex", "multiplex"),
    ):
        value = getattr(settings, attr)
        if value is not None:
            payload[key] = value
    out["httpmask"] = payload


class SudokuCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.SUDOKU
    clash_type = "sudoku"

    def after_parse(self, node: Node, data: dict[str, Any]) -> Node:
        raw = data.get("httpmask")
        if isinstance(raw, Mapping):
            unknown = {
                key: copy.deepcopy(value)
                for key, value in raw.items()
                if key not in _HTTPMASK_KEYS
            }
            if unknown:
                node.source_extensions.setdefault(
                    node.source_context.dialect, {}
                ).update(
                    httpmask=unknown,
                    semantic_fields=[f"httpmask.{key}" for key in unknown],
                )
        return node

    def emit_clash(
        self, node: Node, context: DialectContext | None = None
    ) -> dict[str, Any]:
        context = context or DialectContext("mihomo", "yaml")
        out = super().emit_clash(node, context)
        if (
            node.source_context
            and node.source_context.dialect == context.dialect
            and isinstance(out.get("httpmask"), dict)
        ):
            unknown = node.source_extensions.get(context.dialect, {}).get(
                "httpmask", {}
            )
            for key, value in unknown.items():
                if key not in _HTTPMASK_KEYS:
                    out["httpmask"].setdefault(key, copy.deepcopy(value))
        return out

    target_constraints = {"mihomo": {"features": {"smux"}}}
    fields = (
        scalar_field("key", default="", emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "aead-method",
            "aead_method",
            default="chacha20-poly1305",
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field(
            "padding-min", "padding_min", default=10, emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field(
            "padding-max", "padding_max", default=30, emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field(
            "table-type",
            "table_type",
            default="prefer_entropy",
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field(
            "enable-pure-downlink",
            "enable_pure_downlink",
            default=True,
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field("http-mask", "legacy_http_mask", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "http-mask-mode",
            "legacy_http_mask_mode",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "http-mask-tls",
            "legacy_http_mask_tls",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "http-mask-host",
            "legacy_http_mask_host",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("path-root", "legacy_path_root", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("multiplex", default="off", emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "http-mask-strategy",
            "legacy_http_mask_strategy",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "http-mask-multiplex",
            "legacy_http_mask_multiplex",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        field_group(
            consumed_keys=("httpmask",),
            node_attrs=("httpmask",),
            parse_kwargs=_parse_httpmask,
            emit_into=_emit_httpmask,
        ),
        scalar_field("custom-table", "custom_table", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("custom-tables", "custom_tables", emit_policy=EmitPolicy.NOT_NONE),
        smux_group(),
    )


CODEC = SudokuCodec()
