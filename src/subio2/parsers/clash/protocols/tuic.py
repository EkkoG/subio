"""TUIC protocol parser for Clash."""

from typing import Dict, Any, Optional
from ....models.node import Proxy, TuicProtocol, TLSConfig, ECHConfig
from .registry import register_clash_parser


@register_clash_parser("tuic")
def parse_tuic(data: Dict[str, Any]) -> Optional[Proxy]:
    """Parse TUIC proxy configuration."""
    try:
        protocol = TuicProtocol(
            uuid=data.get("uuid"),
            password=data.get("password"),
            token=data.get("token"),
            congestion_control=data.get("congestion-controller", "cubic"),
            udp_relay_mode=data.get("udp-relay-mode", "native"),
            reduce_rtt=data.get("reduce-rtt", False),
            heartbeat_interval=data.get("heartbeat-interval"),
            alpn=data.get("alpn"),
            disable_sni=data.get("disable-sni", False),
            max_udp_relay_packet_size=data.get("max-udp-relay-packet-size"),
        )

        node = Proxy(
            name=data.get("name", "tuic"),
            server=data.get("server", ""),
            port=data.get("port", 443),
            protocol=protocol,
        )

        # TLS is typically required for TUIC
        tls_config = TLSConfig(
            enabled=True,
            sni=data.get("sni"),
            skip_cert_verify=data.get("skip-cert-verify", False),
            alpn=data.get("alpn"),
            fingerprint=data.get("fingerprint"),
        )

        # Handle ECH
        if data.get("ech-opts"):
            ech_opts = data["ech-opts"]
            if ech_opts.get("enable"):
                tls_config.ech = ECHConfig(enabled=True, config=ech_opts.get("config"))

        node.tls = tls_config

        # Handle extra fields
        if data.get("ip"):
            node.extra["ip"] = data["ip"]

        if data.get("request-timeout"):
            node.extra["request-timeout"] = data["request-timeout"]

        if data.get("cwnd"):
            node.extra["cwnd"] = data["cwnd"]

        if data.get("max-open-streams"):
            node.extra["max-open-streams"] = data["max-open-streams"]

        if data.get("fast-open"):
            node.extra["fast-open"] = data["fast-open"]

        # Handle udp-over-stream (meta/sing-box extension)
        if data.get("udp-over-stream"):
            node.extra["udp-over-stream"] = data["udp-over-stream"]
            if data.get("udp-over-stream-version"):
                node.extra["udp-over-stream-version"] = data["udp-over-stream-version"]

        # Validate protocol
        try:
            protocol.validate()
        except ValueError as e:
            print(f"TUIC validation error: {e}")
            return None

        return node
    except Exception as e:
        print(f"Failed to parse TUIC proxy: {e}")
        return None
