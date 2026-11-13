from dataclasses import dataclass

from subio_v2.adapters.surge.syntax import SurgeProxyRecord
from subio_v2.adapters.surge.validation import _strict_bool as _value_bool
from subio_v2.core.nodes import (
    Network,
    Node,
    TLSSettings,
    TransportSettings,
)


@dataclass(frozen=True)
class SurgeProtocolParseContext:
    record: SurgeProxyRecord
    server: str
    port: int

    @property
    def keyword(self) -> str:
        return self.record.type.lower()

    @property
    def values(self) -> dict[str, str]:
        return self.record.parameters.last_values

    @property
    def positional(self) -> list[str]:
        return list(self.record.positional[2:])

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.values.get(key)
        return default if value is None else _value_bool(value, key)

    def get_int(self, key: str) -> int | None:
        value = self.values.get(key)
        return None if value is None else int(value)

    def build_tls(self, *, enabled: bool = False) -> TLSSettings:
        values = self.values
        sni = values.get("sni")
        alpn = values.get("alpn")
        return TLSSettings(
            enabled=enabled or self.get_bool("tls", False),
            server_name=None if sni == "off" else sni,
            skip_cert_verify=self.get_bool("skip-cert-verify", False),
            alpn=(
                [item.strip() for item in alpn.split(",")]
                if alpn and "," in alpn
                else ([alpn] if alpn else None)
            ),
            sni_disabled=sni == "off",
            verify_name=values.get("server-cert-verify-name"),
            certificate_sha256=values.get("server-cert-fingerprint-sha256"),
            client_cert_ref=values.get("client-cert"),
        )

    def build_transport(self) -> TransportSettings:
        values = self.values
        transport = TransportSettings()
        if values.get("ws") != "true":
            return transport
        transport.network = Network.WS
        transport.path = values.get("ws-path")
        if values.get("ws-headers"):
            transport.headers = _parse_headers(values["ws-headers"])
        return transport


def _parse_headers(value: str, *, separator: str = "|") -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in value.split(separator):
        if ":" not in item:
            continue
        key, header_value = item.split(":", 1)
        headers[key.strip()] = header_value.strip()
    return headers


class _SurgeEmissionError(ValueError):
    def __init__(self, message: str, *, field: str, code: str = "conversion"):
        super().__init__(message)
        self.field = field
        self.code = code


class SurgeServerError(ValueError):
    field = "server"
    code = "conversion.invalid-value"


def _server_str(node: Node) -> str:
    server = node.server
    value = str(server[0]) if isinstance(server, list) else str(server)
    if "=" in value:
        raise SurgeServerError("Surge positional server cannot contain '='")
    return value


def _serialize_headers(headers: dict[str, str], *, separator: str, field: str) -> str:
    # The header consumer splits and strips after the outer Surge quotes decode.
    for key, value in headers.items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or ":" in key
            or separator in key
            or separator in value
            or key != key.strip()
            or value != value.strip()
        ):
            raise _SurgeEmissionError(
                "Surge headers contain an unrepresentable key or value",
                field=field,
                code="conversion.invalid-value",
            )
    return separator.join(f"{key}:{value}" for key, value in headers.items())


def _parameter_bool(values: dict[str, str], key: str, *, default: bool = False) -> bool:
    value = values.get(key)
    if value is None:
        return default
    normalized = value.lower()
    if normalized not in {"true", "false"}:
        raise ValueError(f"{key} must be true or false")
    return normalized == "true"


def _surge_tls(values: dict[str, str], *, enabled: bool = True) -> TLSSettings:
    sni = values.get("sni")
    alpn = values.get("alpn")
    return TLSSettings(
        enabled=enabled,
        server_name=None if sni == "off" else sni,
        skip_cert_verify=values.get("skip-cert-verify") == "true",
        alpn=[part.strip() for part in alpn.split(",")] if alpn else None,
        sni_disabled=sni == "off",
        verify_name=values.get("server-cert-verify-name"),
        certificate_sha256=values.get("server-cert-fingerprint-sha256"),
        client_cert_ref=values.get("client-cert"),
    )


def _validate_opaque_endpoint(record: SurgeProxyRecord) -> None:
    if len(record.positional) < 2:
        raise ValueError("host and port are required")
    port = int(record.positional[1])
    if not record.positional[0] or not 1 <= port <= 65535:
        raise ValueError("host or port is invalid")
