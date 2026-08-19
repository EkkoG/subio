from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

from subio_v2.model.nodes import (
    Node,
    Protocol,
    SudokuHTTPMaskSettings,
    SudokuNode,
)
from subio_v2.protocols._base import NodeValidationError, StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    field_group,
    scalar_field,
    smux_group,
)

_AEAD_METHODS = {"chacha20-poly1305", "aes-128-gcm", "none"}
_TABLE_TYPES = {
    "entropy",
    "prefer_entropy",
    "ascii",
    "prefer_ascii",
    "up_ascii_down_entropy",
    "up_entropy_down_ascii",
}
_HTTP_MASK_MODES = {"legacy", "stream", "poll", "auto", "ws"}
_MULTIPLEX_MODES = {"off", "auto", "on"}
_LEGACY_HTTP_MASK_STRATEGIES = {"random", "post", "websocket"}


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


class SudokuDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SUDOKU
    clash_type = "sudoku"
    fields = (
        scalar_field("key", default="", emit_policy=EmitPolicy.ALWAYS, required=True),
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
        scalar_field(
            "http-mask", "legacy_http_mask", emit_policy=EmitPolicy.NOT_NONE
        ),
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
        scalar_field(
            "path-root", "legacy_path_root", emit_policy=EmitPolicy.NOT_NONE
        ),
        scalar_field(
            "multiplex", default="off", emit_policy=EmitPolicy.ALWAYS
        ),
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
        scalar_field(
            "custom-table", "custom_table", emit_policy=EmitPolicy.NOT_NONE
        ),
        scalar_field(
            "custom-tables", "custom_tables", emit_policy=EmitPolicy.NOT_NONE
        ),
        smux_group(),
    )

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, SudokuNode):
            return errors

        self._validate_enum(errors, "aead_method", node.aead_method, _AEAD_METHODS)
        self._validate_enum(errors, "table_type", node.table_type, _TABLE_TYPES)
        self._validate_enum(errors, "multiplex", node.multiplex, _MULTIPLEX_MODES)
        self._validate_optional_enum(
            errors,
            "legacy_http_mask_mode",
            node.legacy_http_mask_mode,
            _HTTP_MASK_MODES,
        )
        self._validate_optional_enum(
            errors,
            "legacy_http_mask_strategy",
            node.legacy_http_mask_strategy,
            _LEGACY_HTTP_MASK_STRATEGIES,
        )
        self._validate_optional_enum(
            errors,
            "legacy_http_mask_multiplex",
            node.legacy_http_mask_multiplex,
            _MULTIPLEX_MODES,
        )

        for field, value in (
            ("padding_min", node.padding_min),
            ("padding_max", node.padding_max),
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 100
            ):
                errors.append(
                    NodeValidationError(field, f"Sudoku {field} must be between 0 and 100")
                )
        if (
            isinstance(node.padding_min, int)
            and not isinstance(node.padding_min, bool)
            and isinstance(node.padding_max, int)
            and not isinstance(node.padding_max, bool)
            and node.padding_max < node.padding_min
        ):
            errors.append(
                NodeValidationError(
                    "padding_max", "Sudoku padding-max must not be less than padding-min"
                )
            )
        if node.enable_pure_downlink is False and node.aead_method == "none":
            errors.append(
                NodeValidationError(
                    "aead_method",
                    "Sudoku aead-method cannot be none when pure downlink is disabled",
                )
            )

        if node.httpmask is not None:
            if not isinstance(node.httpmask, SudokuHTTPMaskSettings):
                errors.append(
                    NodeValidationError(
                        "httpmask", "Sudoku httpmask must be a mapping"
                    )
                )
            else:
                self._validate_optional_enum(
                    errors, "httpmask.mode", node.httpmask.mode, _HTTP_MASK_MODES
                )
                self._validate_optional_enum(
                    errors,
                    "httpmask.multiplex",
                    node.httpmask.multiplex,
                    _MULTIPLEX_MODES,
                )

        if node.custom_table is not None and not self._valid_custom_table(
            node.custom_table
        ):
            errors.append(
                NodeValidationError(
                    "custom_table",
                    "Sudoku custom-table must contain exactly 2 x, 2 p, and 4 v characters",
                )
            )
        if node.custom_tables is not None:
            if not isinstance(node.custom_tables, list):
                errors.append(
                    NodeValidationError(
                        "custom_tables", "Sudoku custom-tables must be a list"
                    )
                )
            elif any(
                not self._valid_custom_table(value) for value in node.custom_tables
            ):
                errors.append(
                    NodeValidationError(
                        "custom_tables",
                        "Every Sudoku custom table must contain exactly 2 x, 2 p, and 4 v characters",
                    )
                )
        return errors

    @staticmethod
    def _validate_enum(
        errors: list[NodeValidationError],
        field: str,
        value: str,
        supported: set[str],
    ) -> None:
        if value not in supported:
            errors.append(
                NodeValidationError(
                    field, f"Unsupported Sudoku {field.replace('_', '-')}: {value}"
                )
            )

    @classmethod
    def _validate_optional_enum(
        cls,
        errors: list[NodeValidationError],
        field: str,
        value: str | None,
        supported: set[str],
    ) -> None:
        if value is not None:
            cls._validate_enum(errors, field, value, supported)

    @staticmethod
    def _valid_custom_table(value: object) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 8
            and value.count("x") == 2
            and value.count("p") == 2
            and value.count("v") == 4
        )


DESCRIPTOR = SudokuDescriptor()
