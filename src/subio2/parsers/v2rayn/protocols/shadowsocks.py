"""Shadowsocks URL parser for V2rayN format."""

import base64
from typing import Optional
from urllib.parse import urlparse, unquote, parse_qs
from ....models.node import Proxy, ShadowsocksProtocol


def parse(url: str) -> Optional[Proxy]:
    """Parse Shadowsocks URL: ss://base64(method:password)@server:port#name"""
    try:
        parsed = urlparse(url)

        # Initialize variables
        method = None
        password = None
        server = None
        port = None

        # Decode base64 encoded user info
        # Check if it's the new format (has password) or old format (base64)
        if parsed.username and parsed.password is not None:
            # New format: ss://method:password@server:port#name
            method = parsed.username
            password = parsed.password
            server = parsed.hostname
            port = parsed.port
        else:
            # Old format: ss://base64(method:password)@server:port#name
            # Extract the part before @
            if "@" in parsed.netloc:
                encoded, server_part = parsed.netloc.split("@", 1)
                # Parse server and port from the remaining part
                if ":" in server_part:
                    server, port_str = server_part.rsplit(":", 1)
                    port = int(port_str)
                else:
                    server = server_part
                    port = 443  # Default port

                # Decode the base64 part
                try:
                    decoded = base64.b64decode(encoded + "==").decode("utf-8")
                except Exception:
                    decoded = base64.b64decode(encoded).decode("utf-8")

                if ":" in decoded:
                    method, password = decoded.split(":", 1)
            else:
                return None

        name = unquote(parsed.fragment) if parsed.fragment else f"{server}:{port}"

        if not all([method, password, server, port]):
            return None

        # Create protocol config
        protocol = ShadowsocksProtocol(method=method, password=password)

        # Create node
        node = Proxy(name=name, server=server, port=port, protocol=protocol)

        # Handle plugin parameters if present in query
        if parsed.query:
            params = parse_qs(parsed.query)
            if "plugin" in params:
                plugin_info = params["plugin"][0]
                # Parse plugin info (e.g., "obfs-local;obfs=tls;obfs-host=9d4054e.wns.windows.com")
                if ";" in plugin_info:
                    parts = plugin_info.split(";")
                    plugin_name = parts[0]
                    plugin_opts = {}
                    for part in parts[1:]:
                        if "=" in part:
                            key, value = part.split("=", 1)
                            plugin_opts[key] = value
                    protocol.plugin = plugin_name
                    protocol.plugin_opts = plugin_opts

        return node

    except Exception as e:
        print(f"Failed to parse Shadowsocks URL {url[:50]}...: {e}")
        return None
