import copy
import sys
from typing import Any, Dict, List

import yaml

from subio_v2.clash.helpers import (
    CLASH_TYPE_TO_PROTOCOL,
    PASSTHROUGH_PROTOCOLS,
    assign_extra,
    parse_base_fields,
    parse_smux,
    parse_tls,
    parse_transport,
)
from subio_v2.model.nodes import (
    AnyTLSNode,
    ClashPassthroughNode,
    Hysteria2Node,
    HysteriaNode,
    HttpNode,
    Network,
    Protocol,
    ShadowsocksNode,
    ShadowsocksRNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    TrojanNode,
    TUICNode,
    VlessNode,
    VmessNode,
    WireguardNode,
)
from subio_v2.parser.base import BaseParser
from subio_v2.utils.logger import logger


class ClashParser(BaseParser):
    def parse(self, content: Any) -> List:
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
            logger.error(
                f"Invalid Clash config format: Expected dict, got {type(data)}. "
                f"Content preview: {str(content)[:100]}"
            )
            sys.exit(1)

        proxies = data.get("proxies")
        if proxies is None:
            logger.error("Clash config missing 'proxies' key")
            sys.exit(1)

        if not isinstance(proxies, list):
            logger.error("'proxies' is not a list")
            sys.exit(1)

        nodes = []
        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue
            node = self._parse_node(proxy)
            if node:
                nodes.append(node)
        return nodes

    def _parse_node(self, data: Dict[str, Any]):
        node_type = data.get("type")
        if not node_type:
            return None

        protocol = CLASH_TYPE_TO_PROTOCOL.get(node_type)
        if protocol is None:
            logger.warning(f"Unsupported Clash proxy type: {node_type}")
            return None

        if protocol in PASSTHROUGH_PROTOCOLS:
            return self._parse_passthrough(data, protocol)

        try:
            parsers = {
                Protocol.SHADOWSOCKS: self._parse_ss,
                Protocol.SHADOWSOCKSR: self._parse_ssr,
                Protocol.VMESS: self._parse_vmess,
                Protocol.VLESS: self._parse_vless,
                Protocol.TROJAN: self._parse_trojan,
                Protocol.SOCKS5: self._parse_socks5,
                Protocol.HTTP: self._parse_http,
                Protocol.WIREGUARD: self._parse_wireguard,
                Protocol.ANYTLS: self._parse_anytls,
                Protocol.HYSTERIA2: self._parse_hysteria2,
                Protocol.HYSTERIA: self._parse_hysteria,
                Protocol.SSH: self._parse_ssh,
                Protocol.SNELL: self._parse_snell,
                Protocol.TUIC: self._parse_tuic,
            }
            return parsers[protocol](data)
        except Exception as e:
            logger.warning(f"Error parsing node {data.get('name')}: {e}")
            return None

    def _parse_passthrough(self, data: Dict[str, Any], protocol: Protocol) -> ClashPassthroughNode:
        return ClashPassthroughNode(
            type=protocol, raw=copy.deepcopy(data), **parse_base_fields(data)
        )

    def _parse_ss(self, data: Dict[str, Any]) -> ShadowsocksNode:
        handled = {
            "cipher",
            "password",
            "plugin",
            "plugin-opts",
            "smux",
            "udp-over-tcp",
            "udp-over-tcp-version",
            "client-fingerprint",
        }
        node = ShadowsocksNode(
            type=Protocol.SHADOWSOCKS,
            cipher=data.get("cipher", "chacha20-ietf-poly1305"),
            password=data.get("password", ""),
            plugin=data.get("plugin"),
            plugin_opts=data.get("plugin-opts"),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_ssr(self, data: Dict[str, Any]) -> ShadowsocksRNode:
        handled = {
            "cipher",
            "password",
            "obfs",
            "protocol",
            "obfs-param",
            "protocol-param",
            "smux",
        }
        node = ShadowsocksRNode(
            type=Protocol.SHADOWSOCKSR,
            cipher=data.get("cipher", ""),
            password=data.get("password", ""),
            obfs=data.get("obfs", ""),
            ssr_protocol=data.get("protocol", ""),
            obfs_param=data.get("obfs-param"),
            protocol_param=data.get("protocol-param"),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_vmess(self, data: Dict[str, Any]) -> VmessNode:
        tls = parse_tls(data)
        if data.get("network") == "grpc":
            tls.enabled = True
        handled = {
            "uuid",
            "alterId",
            "cipher",
            "global-padding",
            "packet-encoding",
            "tls",
            "servername",
            "sni",
            "alpn",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "reality-opts",
            "ech-opts",
            "certificate",
            "private-key",
            "network",
            "ws-opts",
            "h2-opts",
            "http-opts",
            "grpc-opts",
            "smux",
        }
        node = VmessNode(
            type=Protocol.VMESS,
            uuid=data.get("uuid", ""),
            alter_id=int(data.get("alterId", 0) or 0),
            cipher=data.get("cipher", "auto"),
            global_padding=bool(data.get("global-padding", False)),
            packet_encoding=data.get("packet-encoding"),
            tls=tls,
            transport=parse_transport(data),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_vless(self, data: Dict[str, Any]) -> VlessNode:
        tls = parse_tls(data)
        if data.get("network") == "grpc":
            tls.enabled = True
        handled = {
            "uuid",
            "flow",
            "packet-encoding",
            "tls",
            "servername",
            "sni",
            "alpn",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "reality-opts",
            "ech-opts",
            "certificate",
            "private-key",
            "network",
            "ws-opts",
            "h2-opts",
            "http-opts",
            "grpc-opts",
            "smux",
        }
        node = VlessNode(
            type=Protocol.VLESS,
            uuid=data.get("uuid", ""),
            flow=data.get("flow"),
            packet_encoding=data.get("packet-encoding"),
            tls=tls,
            transport=parse_transport(data),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_trojan(self, data: Dict[str, Any]) -> TrojanNode:
        tls = parse_tls(data)
        if data.get("network") == "grpc":
            tls.enabled = True
        handled = {
            "password",
            "tls",
            "servername",
            "sni",
            "alpn",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "reality-opts",
            "ech-opts",
            "certificate",
            "private-key",
            "network",
            "ws-opts",
            "h2-opts",
            "http-opts",
            "grpc-opts",
            "smux",
        }
        node = TrojanNode(
            type=Protocol.TROJAN,
            password=data.get("password", ""),
            tls=tls,
            transport=parse_transport(data),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_socks5(self, data: Dict[str, Any]) -> Socks5Node:
        handled = {
            "username",
            "password",
            "tls",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
        }
        node = Socks5Node(
            type=Protocol.SOCKS5,
            username=data.get("username"),
            password=data.get("password"),
            tls=parse_tls(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_http(self, data: Dict[str, Any]) -> HttpNode:
        handled = {
            "username",
            "password",
            "headers",
            "tls",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
        }
        node = HttpNode(
            type=Protocol.HTTP,
            username=data.get("username"),
            password=data.get("password"),
            headers=data.get("headers"),
            tls=parse_tls(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_wireguard(self, data: Dict[str, Any]) -> WireguardNode:
        ip_val = data.get("ip")
        allowed_ips: List[str] = []
        interface_ip = ip_val
        if isinstance(ip_val, list):
            allowed_ips = list(ip_val)
        elif ip_val:
            interface_ip = ip_val

        if data.get("allowed-ips"):
            allowed_ips = list(data["allowed-ips"])

        handled = {
            "private-key",
            "public-key",
            "preshared-key",
            "pre-shared-key",
            "ip",
            "ipv6",
            "allowed-ips",
            "reserved",
            "mtu",
            "workers",
            "persistent-keepalive",
            "amnezia-wg-option",
            "peers",
            "remote-dns-resolve",
            "dns",
            "refresh-server-ip-interval",
            "smux",
        }
        node = WireguardNode(
            type=Protocol.WIREGUARD,
            private_key=data.get("private-key", ""),
            public_key=data.get("public-key", ""),
            preshared_key=data.get("preshared-key") or data.get("pre-shared-key"),
            interface_ip=interface_ip,
            interface_ipv6=data.get("ipv6"),
            allowed_ips=allowed_ips or ["0.0.0.0/0", "::/0"],
            reserved=data.get("reserved"),
            mtu=data.get("mtu"),
            workers=data.get("workers"),
            persistent_keepalive=data.get("persistent-keepalive"),
            amnezia_wg_option=data.get("amnezia-wg-option"),
            peers=data.get("peers"),
            remote_dns_resolve=data.get("remote-dns-resolve"),
            dns_servers=data.get("dns"),
            refresh_server_ip_interval=data.get("refresh-server-ip-interval"),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_anytls(self, data: Dict[str, Any]) -> AnyTLSNode:
        tls = parse_tls(data)
        tls.enabled = True
        handled = {
            "password",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
            "idle-session-check-interval",
            "idle-session-timeout",
            "min-idle-session",
        }
        node = AnyTLSNode(
            type=Protocol.ANYTLS,
            password=data.get("password", ""),
            tls=tls,
            idle_session_check_interval=data.get("idle-session-check-interval"),
            idle_session_timeout=data.get("idle-session-timeout"),
            min_idle_session=data.get("min-idle-session"),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_hysteria2(self, data: Dict[str, Any]) -> Hysteria2Node:
        tls = parse_tls(data)
        tls.enabled = True
        handled = {
            "password",
            "ports",
            "hop-interval",
            "up",
            "down",
            "obfs",
            "obfs-password",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "ech-opts",
            "smux",
        }
        node = Hysteria2Node(
            type=Protocol.HYSTERIA2,
            password=data.get("password", ""),
            ports=data.get("ports"),
            hop_interval=data.get("hop-interval"),
            up=data.get("up"),
            down=data.get("down"),
            obfs=data.get("obfs"),
            obfs_password=data.get("obfs-password"),
            tls=tls,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_hysteria(self, data: Dict[str, Any]) -> HysteriaNode:
        tls = parse_tls(data, default_enabled=True)
        handled = {
            "ports",
            "protocol",
            "obfs-protocol",
            "up",
            "down",
            "up-speed",
            "down-speed",
            "auth-str",
            "auth",
            "obfs",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "ech-opts",
            "hop-interval",
            "recv-window-conn",
            "recv-window",
            "disable-mtu-discovery",
            "fast-open",
            "smux",
        }
        node = HysteriaNode(
            type=Protocol.HYSTERIA,
            ports=data.get("ports"),
            hysteria_protocol=data.get("protocol"),
            obfs_protocol=data.get("obfs-protocol"),
            up=data.get("up", ""),
            down=data.get("down", ""),
            up_speed=data.get("up-speed"),
            down_speed=data.get("down-speed"),
            auth_str=data.get("auth-str"),
            auth=data.get("auth"),
            obfs=data.get("obfs"),
            hop_interval=data.get("hop-interval"),
            tls=tls,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_ssh(self, data: Dict[str, Any]) -> SSHNode:
        handled = {
            "username",
            "password",
            "private-key",
            "private-key-passphrase",
            "host-key",
            "host-key-algorithms",
        }
        node = SSHNode(
            type=Protocol.SSH,
            username=data.get("username", ""),
            password=data.get("password"),
            private_key=data.get("private-key"),
            private_key_passphrase=data.get("private-key-passphrase"),
            host_key=data.get("host-key"),
            host_key_algorithms=data.get("host-key-algorithms"),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_snell(self, data: Dict[str, Any]) -> SnellNode:
        obfs_opts = data.get("obfs-opts")
        obfs = None
        obfs_host = None
        if isinstance(obfs_opts, dict):
            obfs = obfs_opts.get("mode")
            obfs_host = obfs_opts.get("host")
        handled = {"psk", "version", "obfs-opts", "smux"}
        node = SnellNode(
            type=Protocol.SNELL,
            psk=data.get("psk", ""),
            version=data.get("version"),
            obfs=obfs,
            obfs_host=obfs_host,
            obfs_opts=obfs_opts,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def _parse_tuic(self, data: Dict[str, Any]) -> TUICNode:
        tls = parse_tls(data, default_enabled=True)
        version = None
        if data.get("uuid") or data.get("password"):
            version = 5
        elif data.get("token"):
            version = 4
        handled = {
            "token",
            "uuid",
            "password",
            "smux",
            "tls",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
            "ech-opts",
            "disable-sni",
        }
        node = TUICNode(
            type=Protocol.TUIC,
            token=data.get("token"),
            password=data.get("password"),
            uuid=data.get("uuid"),
            version=version,
            tls=tls,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node
