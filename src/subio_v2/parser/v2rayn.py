import base64
import json
import urllib.parse
from typing import Any
from subio_v2.conversion import ConversionIssue, IssueSeverity, ParseResult
from subio_v2.dialect import DialectContext
from subio_v2.parser.base import BaseParser
from subio_v2.model.nodes import (
    Node,
    ShadowsocksNode,
    VmessNode,
    VlessNode,
    TrojanNode,
    Protocol,
    TLSSettings,
    TransportSettings,
    Network,
)
from subio_v2.utils.logger import logger


class V2RayNParser(BaseParser):
    @staticmethod
    def _network(value: str) -> Network | str:
        try:
            return Network(value)
        except ValueError:
            return value

    def parse_result(self, content: Any) -> ParseResult:
        if not isinstance(content, str):
            raise ValueError("Invalid content type for V2RayNParser")

        # Try decoding base64 if it looks like a subscription
        try:
            decoded = base64.b64decode(content).decode("utf-8")
            lines = decoded.splitlines()
        except Exception:
            lines = content.splitlines()

        nodes: list[Node] = []
        issues: list[ConversionIssue] = []
        for index, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            node = self._parse_line(line)
            if node:
                node.source_context = DialectContext("v2rayn", "text")
                nodes.append(node)
                continue
            scheme = line.partition("://")[0] or None
            fragment = urllib.parse.urlparse(line).fragment
            issues.append(
                ConversionIssue(
                    severity=IssueSeverity.ERROR,
                    node=urllib.parse.unquote(fragment) if fragment else None,
                    protocol=scheme,
                    source=None,
                    target=None,
                    field=f"lines[{index}]",
                    message="Failed to parse v2rayN subscription link",
                    stage="parse",
                    code="parse.link",
                )
            )
        return ParseResult(nodes=nodes, issues=issues)

    def _parse_line(self, line: str) -> Node | None:
        if line.startswith("vmess://"):
            return self._parse_vmess(line)
        elif line.startswith("ss://"):
            return self._parse_ss(line)
        elif line.startswith("trojan://"):
            return self._parse_trojan(line)
        elif line.startswith("vless://"):
            return self._parse_vless(line)
        return None

    def _parse_vmess(self, line: str) -> VmessNode | None:
        try:
            b64 = line[8:]
            # fix padding
            b64 += "=" * ((4 - len(b64) % 4) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8"))

            # Map v2rayN JSON format to VmessNode
            # {
            # "v": "2", "ps": "name", "add": "server", "port": "443", "id": "uuid",
            # "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "",
            # "path": "/", "tls": "tls", "sni": "", "alpn": ""
            # }

            network = data.get("net", "tcp")
            transport = TransportSettings(network=self._network(network))
            if network == Network.WS.value:
                transport.path = data.get("path")
                if data.get("host"):
                    transport.headers = {"Host": data["host"]}
            elif network == Network.H2.value:
                transport.path = data.get("path")
                if data.get("host"):
                    transport.host = data["host"].split(",")
            elif network == Network.GRPC.value:
                transport.grpc_service_name = data.get("path")
            elif network == Network.HTTP.value:
                transport.path = data.get("path")
                if data.get("host"):
                    transport.headers = {"Host": data["host"]}

            tls = TLSSettings(
                enabled=data.get("tls") == "tls",
                server_name=data.get("sni") or data.get("host"),
                alpn=data.get("alpn", "").split(",") if data.get("alpn") else None,
            )
            return VmessNode(
                name=data.get("ps", "VMess"),
                type=Protocol.VMESS,
                server=data.get("add"),
                port=int(data.get("port")),
                uuid=data.get("id"),
                alter_id=int(data.get("aid", 0)),
                cipher=data.get("scy", "auto"),
                transport=transport,
                tls=tls,
            )
        except Exception as e:
            logger.warning(f"Error parsing vmess: {e}")
            return None

    def _parse_ss(self, line: str) -> ShadowsocksNode | None:
        try:
            # Handle ss://base64#name and ss://method:pass@host:port#name
            url = urllib.parse.urlparse(line)

            # Check if userinfo is base64 encoded
            if not url.hostname:
                # Likely ss://BASE64#name
                decoded = base64.b64decode(
                    url.netloc + "=" * ((4 - len(url.netloc) % 4) % 4)
                ).decode("utf-8")
                # method:pass@server:port
                if "@" in decoded:
                    userinfo, hostport = decoded.split("@", 1)
                    method, password = userinfo.split(":", 1)
                    server, port_str = hostport.split(":", 1)
                    port = int(port_str)
                else:
                    # Old style: method:pass:server:port ?? Rare
                    return None
            else:
                # ss://method:pass@server:port
                server = url.hostname
                port = url.port

                # userinfo is usually base64(method:pass) if not plain
                # But standard URI is plain method:pass
                # Let's assume standard first, or check for legacy v2rayn mixing
                if url.username and ":" not in url.username and not url.password:
                    # decode username as base64(method:pass)
                    decoded_auth = base64.b64decode(
                        url.username + "=" * ((4 - len(url.username) % 4) % 4)
                    ).decode("utf-8")
                    method, password = decoded_auth.split(":", 1)
                else:
                    method = url.username
                    password = url.password

            name = (
                urllib.parse.unquote(url.fragment)
                if url.fragment
                else f"{server}:{port}"
            )

            # Plugin support from query params
            q = urllib.parse.parse_qs(url.query)
            plugin = q.get("plugin")
            plugin_opts = None
            if plugin:
                # plugin=obfs-local;obfs=http...
                parts = plugin[0].split(";")
                plugin_name = parts[0]
                plugin_opts = {}
                for p in parts[1:]:
                    if "=" in p:
                        k, v = p.split("=", 1)
                        plugin_opts[k] = v
                plugin = plugin_name

            return ShadowsocksNode(
                name=name,
                type=Protocol.SHADOWSOCKS,
                server=server,
                port=port,
                cipher=method,
                password=password,
                plugin=plugin,
                plugin_opts=plugin_opts,
            )

        except Exception as e:
            logger.warning(f"Error parsing ss: {e}")
            return None

    def _parse_trojan(self, line: str) -> TrojanNode | None:
        try:
            url = urllib.parse.urlparse(line)
            password = url.username
            server = url.hostname
            port = url.port
            name = (
                urllib.parse.unquote(url.fragment)
                if url.fragment
                else f"{server}:{port}"
            )

            q = urllib.parse.parse_qs(url.query)
            sni = q.get("sni", [None])[0]
            allow_insecure = q.get("allowInsecure", ["0"])[0] == "1"
            type_net = q.get("type", ["tcp"])[0]
            transport = TransportSettings(network=self._network(type_net))
            if type_net == Network.WS.value:
                transport.path = q.get("path", [None])[0]
                if q.get("host"):
                    transport.headers = {"Host": q["host"][0]}
            elif type_net == Network.H2.value:
                transport.path = q.get("path", [None])[0]
                if q.get("host"):
                    transport.host = q["host"][0].split(",")
            elif type_net == Network.GRPC.value:
                transport.grpc_service_name = q.get("serviceName", [None])[0]

            security = q.get("security", ["tls"])[0]
            reality_opts = None
            if security == "reality":
                reality_opts = {
                    "public-key": q.get("pbk", [""])[0],
                    "short-id": q.get("sid", [""])[0],
                }

            return TrojanNode(
                name=name,
                type=Protocol.TROJAN,
                server=server,
                port=port,
                password=password,
                tls=TLSSettings(
                    enabled=True,
                    server_name=sni or server,
                    skip_cert_verify=allow_insecure,
                    client_fingerprint=q.get("fp", [None])[0],
                    reality_opts=reality_opts,
                ),
                transport=transport,
            )
        except Exception as e:
            logger.warning(f"Error parsing trojan: {e}")
            return None

    def _parse_vless(self, line: str) -> VlessNode | None:
        try:
            url = urllib.parse.urlparse(line)
            uuid = url.username
            server = url.hostname
            port = url.port
            name = (
                urllib.parse.unquote(url.fragment)
                if url.fragment
                else f"{server}:{port}"
            )

            q = urllib.parse.parse_qs(url.query)
            type_net = q.get("type", ["tcp"])[0]
            security = q.get("security", ["none"])[0]
            flow = q.get("flow", [None])[0]

            transport = TransportSettings(network=self._network(type_net))
            if type_net == Network.WS.value:
                transport.path = q.get("path", [None])[0]
                if q.get("host"):
                    transport.headers = {"Host": q["host"][0]}
            elif type_net == Network.H2.value:
                transport.path = q.get("path", [None])[0]
                if q.get("host"):
                    transport.host = q["host"][0].split(",")
            elif type_net == Network.GRPC.value:
                transport.grpc_service_name = q.get("serviceName", [None])[0]
            elif type_net == Network.HTTP.value:
                path = q.get("path", [None])[0]
                transport.path = path.split(",") if path else None
                if q.get("host"):
                    transport.headers = {"Host": q["host"][0]}

            tls = TLSSettings(
                enabled=(security == "tls" or security == "reality"),
                server_name=q.get("sni", [None])[0],
                skip_cert_verify=q.get("allowInsecure", ["0"])[0] == "1",
                client_fingerprint=q.get("fp", [None])[0],
                reality_opts={
                    "public-key": q.get("pbk", [""])[0],
                    "short-id": q.get("sid", [""])[0],
                }
                if security == "reality"
                else None,
            )
            return VlessNode(
                name=name,
                type=Protocol.VLESS,
                server=server,
                port=port,
                uuid=uuid,
                flow=flow,
                tls=tls,
                transport=transport,
            )
        except Exception as e:
            logger.warning(f"Error parsing vless: {e}")
            return None
