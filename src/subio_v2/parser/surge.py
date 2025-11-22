from typing import List, Any, Dict
from subio_v2.parser.base import BaseParser
from subio_v2.model.nodes import (
    Node, ShadowsocksNode, VmessNode, TrojanNode, 
    Socks5Node, HttpNode, Protocol, TLSSettings, TransportSettings, Network
)

class SurgeParser(BaseParser):
    def parse(self, content: Any) -> List[Node]:
        if not isinstance(content, str):
            return []
        
        lines = content.splitlines()
        nodes = []
        in_proxy_section = False
        
        # Check if there are sections
        has_sections = any(l.strip().startswith("[Proxy]") for l in lines)
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            
            if line.lower() == "[proxy]":
                in_proxy_section = True
                continue
            elif line.startswith("[") and line.endswith("]"):
                in_proxy_section = False
                continue
            
            # If no sections found, treat whole file as proxy list if it looks like it?
            # But Surge conf usually has sections.
            # If we are in proxy section or if the file has no sections (just a list of nodes), parse.
            if in_proxy_section or (not has_sections and "=" in line and "," in line):
                node = self._parse_line(line)
                if node:
                    nodes.append(node)
                else:
                    # print(f"Failed to parse line: {line}")
                    pass
                    
        return nodes


    def _parse_line(self, line: str) -> Node | None:
        # Name = Type, Server, Port, ...
        if "=" not in line:
            return None
            
        name, config_str = line.split("=", 1)
        name = name.strip()
        # Surge allows commas inside values? Usually not for basic proxy line unless escaped?
        parts = [p.strip() for p in config_str.split(",")]
        
        if len(parts) < 3:
            return None
            
        p_type = parts[0].lower()

        server = parts[1]
        try:
            port = int(parts[2])
        except ValueError:
            return None
            
        kv_args = {}
        pos_args = []
        
        for p in parts[3:]:
            if "=" in p:
                k, v = p.split("=", 1)
                kv_args[k.strip()] = v.strip()
            else:
                pos_args.append(p)

        # Helper to get bool
        def get_bool(k, default=False):
            v = kv_args.get(k)
            if v is None: return default
            return v.lower() == "true"
        
        # Remove print(f"Parsing Surge content...") if it exists (already removed?)


        tls = TLSSettings(
            enabled=kv_args.get("tls") == "true",
            server_name=kv_args.get("sni"),
            skip_cert_verify=kv_args.get("skip-cert-verify") == "true"
        )
        
        transport = TransportSettings()
        if kv_args.get("ws") == "true":
            transport.network = Network.WS
            transport.path = kv_args.get("ws-path")
            if kv_args.get("ws-headers"):
                # header1:value1|header2:value2
                headers = {}
                for h in kv_args["ws-headers"].split("|"):
                    if ":" in h:
                        hk, hv = h.split(":", 1)
                        headers[hk.strip()] = hv.strip()
                transport.headers = headers

        if p_type == "ss":
            # ss, server, port, encrypt-method=..., password=...
            # or ss, server, port, encrypt-method, password
            cipher = kv_args.get("encrypt-method")
            password = kv_args.get("password")
            
            # Handle positional args for legacy SS format if needed?
            # Surge typically uses kv args for SS now.
            
            plugin = None
            plugin_opts = None
            if kv_args.get("obfs"):
                plugin = "obfs"
                plugin_opts = {
                    "mode": kv_args["obfs"],
                    "host": kv_args.get("obfs-host", "")
                }

            return ShadowsocksNode(
                name=name,
                type=Protocol.SHADOWSOCKS,
                server=server,
                port=port,
                cipher=cipher or "chacha20-ietf-poly1305",
                password=password or "",
                plugin=plugin,
                plugin_opts=plugin_opts,
                udp=get_bool("udp-relay", False)
            )
            
        elif p_type == "vmess":
            # vmess, server, port, username=..., encrypt-method=...
            
            # Check for TLS implicit
            if kv_args.get("tls") == "true":
                tls.enabled = True
            
            return VmessNode(
                name=name,
                type=Protocol.VMESS,
                server=server,
                port=port,
                uuid=kv_args.get("username", ""),
                cipher=kv_args.get("encrypt-method", "auto"),
                tls=tls,
                transport=transport,
                udp=get_bool("udp-relay", False)
            )
            
        elif p_type == "trojan":
             # trojan, server, port, password=...
             tls.enabled = True # Always TLS
             
             return TrojanNode(
                name=name,
                type=Protocol.TROJAN,
                server=server,
                port=port,
                password=kv_args.get("password", ""),
                tls=tls,
                transport=transport,
                udp=get_bool("udp-relay", False)
             )
             
        elif p_type in ["socks5", "socks5-tls"]:
            if p_type == "socks5-tls":
                tls.enabled = True
            
            # socks5, server, port, username, password (optional positional)
            username = kv_args.get("username")
            password = kv_args.get("password")
            
            if not username and len(pos_args) > 0:
                username = pos_args[0]
            if not password and len(pos_args) > 1:
                password = pos_args[1]

            return Socks5Node(
                name=name,
                type=Protocol.SOCKS5,
                server=server,
                port=port,
                username=username,
                password=password,
                tls=tls,
                udp=get_bool("udp-relay", False)
            )
            
        elif p_type in ["http", "https"]:
            if p_type == "https":
                tls.enabled = True
                
            username = kv_args.get("username")
            password = kv_args.get("password")
            
            if not username and len(pos_args) > 0:
                username = pos_args[0]
            if not password and len(pos_args) > 1:
                password = pos_args[1]
                
            return HttpNode(
                name=name,
                type=Protocol.HTTP,
                server=server,
                port=port,
                username=username,
                password=password,
                tls=tls
            )

        return None

