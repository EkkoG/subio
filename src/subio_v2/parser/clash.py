import yaml
import sys
from typing import List, Any, Dict
from subio_v2.parser.base import BaseParser
from subio_v2.model.nodes import (
    Node,
    ShadowsocksNode,
    VmessNode,
    VlessNode,
    TrojanNode,
    Socks5Node,
    HttpNode,
    WireguardNode,
    AnyTLSNode,
    Hysteria2Node,
    Protocol,
    TLSSettings,
    TransportSettings,
    SmuxSettings,
    Network,
)
from subio_v2.utils.logger import logger


class ClashParser(BaseParser):
    def parse(self, content: Any) -> List[Node]:
        if isinstance(content, str):
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                logger.error(f"YAML parse error: {e}")
                sys.exit(1)
        elif isinstance(content, dict):
            data = content
        else:
            logger.error("Invalid content type for ClashParser")
            sys.exit(1)

        if not isinstance(data, dict):
            logger.error(f"Invalid Clash config format: Expected dict, got {type(data)}. Content preview: {str(content)[:100]}")
            sys.exit(1)

        proxies = data.get("proxies")
        if proxies is None:
             # Some providers return just a list of proxies without "proxies" key?
             # Or maybe it's a different format?
             # If strict clash, it must have proxies.
             # If it's just a list, maybe handle it?
             # But standard clash config has "proxies".
             logger.error("Clash config missing 'proxies' key")
             sys.exit(1)
             
        if not isinstance(proxies, list):
             logger.error("'proxies' is not a list")
             sys.exit(1)

        nodes = []
        for proxy in proxies:
            node = self._parse_node(proxy)
            if node:
                nodes.append(node)
        return nodes

    def _parse_node(self, data: Dict[str, Any]) -> Node | None:
        node_type = data.get("type")

        try:
            if node_type == "ss":
                return self._parse_ss(data)
            elif node_type == "vmess":
                return self._parse_vmess(data)
            elif node_type == "vless":
                return self._parse_vless(data)
            elif node_type == "trojan":
                return self._parse_trojan(data)
            elif node_type == "socks5":
                return self._parse_socks5(data)
            elif node_type == "http":
                return self._parse_http(data)
            elif node_type == "wireguard":
                return self._parse_wireguard(data)
            elif node_type == "anytls":
                return self._parse_anytls(data)
            elif node_type == "hysteria2":
                return self._parse_hysteria2(data)
        except Exception as e:
            # Log error but continue
            logger.warning(f"Error parsing node {data.get('name')}: {e}")
            return None

        return None

    def _base_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": data.get("name", "Unknown"),
            "server": data.get("server", ""),
            "port": int(data.get("port", 0)),
            "udp": data.get("udp", True),
            "ip_version": data.get("ip-version", "dual"),
            "tfo": data.get("tfo", False),
            "mptcp": data.get("mptcp", False),
            "dialer_proxy": data.get("dialer-proxy"),
        }

    def _parse_tls(self, data: Dict[str, Any]) -> TLSSettings:
        # Hysteria2 might have ech options
        ech = None
        if data.get("ech-opts"):
            ech = data["ech-opts"]

        return TLSSettings(
            enabled=data.get("tls", False),
            server_name=data.get("servername") or data.get("sni"),
            alpn=data.get("alpn"),
            skip_cert_verify=data.get("skip-cert-verify", False),
            fingerprint=data.get("fingerprint"),
            client_fingerprint=data.get("client-fingerprint"),
            reality_opts=data.get("reality-opts"),
            ech_opts=ech,
            certificate=data.get("certificate"),
            private_key=data.get("private-key"),
        )

    def _parse_transport(self, data: Dict[str, Any]) -> TransportSettings:
        net = data.get("network", "tcp")
        return TransportSettings(
            network=Network(net) if net in [n.value for n in Network] else Network.TCP,
            path=data.get("ws-opts", {}).get("path")
            or data.get("h2-opts", {}).get("path")
            or data.get("http-opts", {}).get("path"),
            headers=data.get("ws-opts", {}).get("headers")
            or data.get("http-opts", {}).get("headers"),
            host=data.get("h2-opts", {}).get("host"),
            method=data.get("http-opts", {}).get("method"),
            grpc_service_name=data.get("grpc-opts", {}).get("grpc-service-name"),
            max_early_data=data.get("ws-opts", {}).get("max-early-data"),
            early_data_header_name=data.get("ws-opts", {}).get(
                "early-data-header-name"
            ),
        )

    def _parse_smux(self, data: Dict[str, Any]) -> SmuxSettings:
        smux_data = data.get("smux", {})
        if not smux_data:
            return SmuxSettings()
        return SmuxSettings(
            enabled=smux_data.get("enabled", False),
            protocol=smux_data.get("protocol", "smux"),
            max_connections=smux_data.get("max-connections", 4),
            min_streams=smux_data.get("min-streams", 4),
            max_streams=smux_data.get("max-streams", 0),
            padding=smux_data.get("padding", False),
            brutal_opts=smux_data.get("brutal-opts"),
        )

    def _parse_ss(self, data: Dict[str, Any]) -> ShadowsocksNode:
        return ShadowsocksNode(
            type=Protocol.SHADOWSOCKS,
            cipher=data.get("cipher", "chacha20-ietf-poly1305"),
            password=data.get("password", ""),
            plugin=data.get("plugin"),
            plugin_opts=data.get("plugin-opts"),
            **self._base_fields(data),
        )

    def _parse_vmess(self, data: Dict[str, Any]) -> VmessNode:
        return VmessNode(
            type=Protocol.VMESS,
            uuid=data.get("uuid", ""),
            alter_id=data.get("alterId", 0),
            cipher=data.get("cipher", "auto"),
            global_padding=data.get("global-padding", False),
            packet_encoding=data.get("packet-encoding"),
            tls=self._parse_tls(data),
            transport=self._parse_transport(data),
            smux=self._parse_smux(data),
            **self._base_fields(data),
        )

    def _parse_vless(self, data: Dict[str, Any]) -> VlessNode:
        return VlessNode(
            type=Protocol.VLESS,
            uuid=data.get("uuid", ""),
            flow=data.get("flow"),
            packet_encoding=data.get("packet-encoding"),
            tls=self._parse_tls(data),
            transport=self._parse_transport(data),
            smux=self._parse_smux(data),
            **self._base_fields(data),
        )

    def _parse_trojan(self, data: Dict[str, Any]) -> TrojanNode:
        return TrojanNode(
            type=Protocol.TROJAN,
            password=data.get("password", ""),
            tls=self._parse_tls(data),
            transport=self._parse_transport(data),
            smux=self._parse_smux(data),
            **self._base_fields(data),
        )

    def _parse_socks5(self, data: Dict[str, Any]) -> Socks5Node:
        return Socks5Node(
            type=Protocol.SOCKS5,
            username=data.get("username"),
            password=data.get("password"),
            tls=self._parse_tls(data),
            **self._base_fields(data),
        )

    def _parse_http(self, data: Dict[str, Any]) -> HttpNode:
        return HttpNode(
            type=Protocol.HTTP,
            username=data.get("username"),
            password=data.get("password"),
            headers=data.get("headers"),
            tls=self._parse_tls(data),
            **self._base_fields(data),
        )

    def _parse_wireguard(self, data: Dict[str, Any]) -> WireguardNode:
        return WireguardNode(
            type=Protocol.WIREGUARD,
            private_key=data.get("private-key", ""),
            public_key=data.get("public-key", ""),
            preshared_key=data.get("preshared-key"),
            endpoint=data.get("udp", False),
            allowed_ips=data.get("ip", []) if isinstance(data.get("ip"), list) else [],
            **self._base_fields(data),
        )

    def _parse_anytls(self, data: Dict[str, Any]) -> AnyTLSNode:
        tls = self._parse_tls(data)
        tls.enabled = True

        return AnyTLSNode(
            type=Protocol.ANYTLS,
            password=data.get("password", ""),
            tls=tls,
            idle_session_check_interval=data.get("idle-session-check-interval"),
            idle_session_timeout=data.get("idle-session-timeout"),
            min_idle_session=data.get("min-idle-session"),
            **self._base_fields(data),
        )

    def _parse_hysteria2(self, data: Dict[str, Any]) -> Hysteria2Node:
        tls = self._parse_tls(data)
        # Hysteria2 uses TLS implicitly usually, but can be disabled (not standard).
        # The config fields (sni, skip-cert-verify, etc) are at root. _parse_tls handles them.
        tls.enabled = True

        return Hysteria2Node(
            type=Protocol.HYSTERIA2,
            password=data.get("password", ""),
            ports=data.get("ports"),
            hop_interval=data.get("hop-interval"),
            up=data.get("up"),
            down=data.get("down"),
            obfs=data.get("obfs"),
            obfs_password=data.get("obfs-password"),
            tls=tls,
            **self._base_fields(data),
        )
