from __future__ import annotations

from typing import Any

from subio_v2.surge.syntax import SurgeProxyRecord


class _ExternalAuthorizationMarker:
    def __deepcopy__(self, memo: dict[int, Any]) -> "_ExternalAuthorizationMarker":
        return self


_AUTHORIZED_EXTERNAL = _ExternalAuthorizationMarker()


def authorize_local_external(node: Any) -> None:
    extension = node.source_extensions.setdefault("surge", {})
    extension["_external_authorization"] = _AUTHORIZED_EXTERNAL


def is_authorized_local_external(node: Any) -> bool:
    extension = node.source_extensions.get("surge", {})
    return extension.get("_external_authorization") is _AUTHORIZED_EXTERNAL


def validate_external_record(record: Any) -> dict[str, str]:
    if not isinstance(record, SurgeProxyRecord) or record.type.lower() != "external":
        raise ValueError("External node does not contain a valid Surge proxy record")
    values = record.parameters.last_values
    if not values.get("exec"):
        raise ValueError("External exec is required")
    try:
        local_port = int(values.get("local-port", ""))
    except ValueError:
        raise ValueError("External local-port must be an integer") from None
    if not 1 <= local_port <= 65535:
        raise ValueError("External local-port must be between 1 and 65535")
    if values.get("udp-relay") not in {None, "true", "false"}:
        raise ValueError("External udp-relay must be true or false")
    return values
