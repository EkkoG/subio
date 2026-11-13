from __future__ import annotations

from subio_v2.core.nodes import (
    Node,
    Protocol,
    SudokuHTTPMaskSettings,
    SudokuNode,
)
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec

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


def _validate(node: Node) -> list[NodeValidationError]:
    errors: list[NodeValidationError] = []
    if not isinstance(node, SudokuNode):
        return errors

    _validate_enum(errors, "aead_method", node.aead_method, _AEAD_METHODS)
    _validate_enum(errors, "table_type", node.table_type, _TABLE_TYPES)
    _validate_enum(errors, "multiplex", node.multiplex, _MULTIPLEX_MODES)
    _validate_optional_enum(
        errors,
        "legacy_http_mask_mode",
        node.legacy_http_mask_mode,
        _HTTP_MASK_MODES,
    )
    _validate_optional_enum(
        errors,
        "legacy_http_mask_strategy",
        node.legacy_http_mask_strategy,
        _LEGACY_HTTP_MASK_STRATEGIES,
    )
    _validate_optional_enum(
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
                NodeValidationError("httpmask", "Sudoku httpmask must be a mapping")
            )
        else:
            _validate_optional_enum(
                errors, "httpmask.mode", node.httpmask.mode, _HTTP_MASK_MODES
            )
            _validate_optional_enum(
                errors,
                "httpmask.multiplex",
                node.httpmask.multiplex,
                _MULTIPLEX_MODES,
            )

    if node.custom_table is not None and not _valid_custom_table(node.custom_table):
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
        elif any(not _valid_custom_table(value) for value in node.custom_tables):
            errors.append(
                NodeValidationError(
                    "custom_tables",
                    "Every Sudoku custom table must contain exactly 2 x, 2 p, and 4 v characters",
                )
            )
    return errors


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


def _validate_optional_enum(
    errors: list[NodeValidationError],
    field: str,
    value: str | None,
    supported: set[str],
) -> None:
    if value is not None:
        _validate_enum(errors, field, value, supported)


def _valid_custom_table(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 8
        and value.count("x") == 2
        and value.count("p") == 2
        and value.count("v") == 4
    )


SPEC = ProtocolSpec(
    protocol=Protocol.SUDOKU,
    required_fields=("key",),
    validator=_validate,
    node_class=SudokuNode,
    user_override_fields=frozenset({"server", "port"}),
    terminal_native_user_override_fields=frozenset({"server", "port"}),
    terminal_native_fields=frozenset(
        {
            "aead_method",
            "custom_table",
            "custom_tables",
            "enable_pure_downlink",
            "httpmask",
            "key",
            "legacy_http_mask",
            "legacy_http_mask_host",
            "legacy_http_mask_mode",
            "legacy_http_mask_multiplex",
            "legacy_http_mask_strategy",
            "legacy_http_mask_tls",
            "legacy_path_root",
            "multiplex",
            "padding_max",
            "padding_min",
            "smux",
            "table_type",
        }
    ),
)
