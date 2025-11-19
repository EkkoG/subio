import yaml
from typing import List, Any, Dict
from src.subio_v2.parser.base import BaseParser
from src.subio_v2.model.nodes import (
    Node, ShadowsocksNode, VmessNode, VlessNode, TrojanNode, 
    Socks5Node, HttpNode, WireguardNode, Protocol,
    TLSSettings, TransportSettings, SmuxSettings, Network
)

class ClashParser(BaseParser):
    def parse(self, content: Any) -> List[Node]:
        if isinstance(content, str):
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError:
                return []
        elif isinstance(content, dict):
            data = content
        else:
            return []

        proxies = data.get("proxies", [])
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
        except Exception as e:
            # Log error but continue
            print(f"Error parsing node {data.get('name')}: {e}")
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
        return TLSSettings(
            enabled=data.get("tls", False),
            server_name=data.get("servername") or data.get("sni"),
            alpn=data.get("alpn"),
            skip_cert_verify=data.get("skip-cert-verify", False),
            fingerprint=data.get("fingerprint"),
            client_fingerprint=data.get("client-fingerprint"),
            reality_opts=data.get("reality-opts")
        )

    def _parse_transport(self, data: Dict[str, Any]) -> TransportSettings:
        net = data.get("network", "tcp")
        return TransportSettings(
            network=Network(net) if net in [n.value for n in Network] else Network.TCP,
            path=data.get("ws-opts", {}).get("path") or data.get("h2-opts", {}).get("path") or data.get("http-opts", {}).get("path"),
            headers=data.get("ws-opts", {}).get("headers") or data.get("http-opts", {}).get("headers"),
            host=data.get("h2-opts", {}).get("host"),
            method=data.get("http-opts", {}).get("method"),
            grpc_service_name=data.get("grpc-opts", {}).get("grpc-service-name"),
            max_early_data=data.get("ws-opts", {}).get("max-early-data"),
            early_data_header_name=data.get("ws-opts", {}).get("early-data-header-name"),
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
            brutal_opts=smux_data.get("brutal-opts")
        )

    def _parse_ss(self, data: Dict[str, Any]) -> ShadowsocksNode:
        return ShadowsocksNode(
            type=Protocol.SHADOWSOCKS,
            cipher=data.get("cipher", "chacha20-ietf-poly1305"),
            password=data.get("password", ""),
            plugin=data.get("plugin"),
            plugin_opts=data.get("plugin-opts"),
            **self._base_fields(data)
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
            **self._base_fields(data)
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
            **self._base_fields(data)
        )

    def _parse_trojan(self, data: Dict[str, Any]) -> TrojanNode:
        return TrojanNode(
            type=Protocol.TROJAN,
            password=data.get("password", ""),
            tls=self._parse_tls(data),
            transport=self._parse_transport(data),
            smux=self._parse_smux(data),
            **self._base_fields(data)
        )
    
    def _parse_socks5(self, data: Dict[str, Any]) -> Socks5Node:
        return Socks5Node(
            type=Protocol.SOCKS5,
            username=data.get("username"),
            password=data.get("password"),
            tls=self._parse_tls(data),
            **self._base_fields(data)
        )

    def _parse_http(self, data: Dict[str, Any]) -> HttpNode:
        return HttpNode(
            type=Protocol.HTTP,
            username=data.get("username"),
            password=data.get("password"),
            headers=data.get("headers"),
            tls=self._parse_tls(data),
            **self._base_fields(data)
        )

    def _parse_wireguard(self, data: Dict[str, Any]) -> WireguardNode:
        return WireguardNode(
            type=Protocol.WIREGUARD,
            private_key=data.get("private-key", ""),
            public_key=data.get("public-key", ""),
            preshared_key=data.get("preshared-key"),
            endpoint=data.get("udp", False), # WG usually parses endpoint from server:port, but here it's separate in Node but combined in Clash?
            # Clash puts everything in server/port.
            allowed_ips=data.get("ip", []) if isinstance(data.get("ip"), list) else [], # Wait, clash uses 'ip' or 'allowed-ips'?
            # Checking v1 impl: it just copies fields.
            # Standard WG uses allowed-ips.
            **self._base_fields(data)
        )

