import pytest

from subio_v2.conversion import IssueSeverity
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.model.nodes import Protocol
from subio_v2.parser.surge import SurgeParser


def test_surge_parser_proxy_section_and_no_sections():
    conf = """
[Proxy]
SS1 = ss, s1, 1000, encrypt-method=aes-256-gcm, password=p, udp-relay=true, obfs=http, obfs-host=h
VM2 = vmess, s2, 2000, username=u2, encrypt-method=auto, tls=true
TRO3 = trojan, s3, 3000, password=tp
SOCK = socks5, s4, 4000, username=user, password=pass
HTTP = https, s5, 5000, username=aa, password=bb
"""
    nodes = SurgeParser().parse(conf)
    names = [n.name for n in nodes]
    assert names == ["SS1", "VM2", "TRO3", "SOCK", "HTTP"]
    assert nodes[0].type == Protocol.SHADOWSOCKS and nodes[0].plugin == "obfs"
    assert nodes[1].type == Protocol.VMESS and nodes[1].tls.enabled
    assert nodes[2].type == Protocol.TROJAN and nodes[2].tls.enabled
    assert nodes[3].type == Protocol.SOCKS5 and nodes[3].username == "user"
    assert nodes[4].type == Protocol.HTTP and nodes[4].tls.enabled

    # No sections style line
    conf2 = "SSa = ss, s, 1, encrypt-method=aes-256-gcm, password=p\nBadLine"
    nodes2 = SurgeParser().parse(conf2)
    assert [n.name for n in nodes2] == ["SSa"]


def test_surge_parser_invalid_types_and_values_skip_line():
    conf = "Bad = vmess, s, notaport\n[Proxy]\nN = vmess, s, 80, tls=true"
    nodes = SurgeParser().parse(conf)
    assert [n.name for n in nodes] == ["N"]


def test_surge_invalid_content_type_exits():
    with pytest.raises(SystemExit):
        SurgeParser().parse({"not": "str"})

    with pytest.raises(ValueError, match="Invalid content type"):
        SurgeParser().parse_result({"not": "str"})


def test_surge_parse_result_reports_bad_lines_and_missing_wireguard_resource():
    result = SurgeParser().parse_result(
        """
[Proxy]
good = ss, example.com, 8388, encrypt-method=aes-256-gcm, password=p
bad = vmess, example.com, not-a-port, username=u
wg = wireguard, section-name, 0
"""
    )

    assert [node.name for node in result.nodes] == ["good"]
    assert [(issue.code, issue.severity) for issue in result.issues] == [
        ("parse.line", IssueSeverity.ERROR),
        ("parse.resource", IssueSeverity.ERROR),
    ]
    assert result.issues[0].node == "bad"
    assert result.issues[0].protocol == "vmess"
    assert result.issues[0].field == "lines[3]"


def test_surge_parse_result_reports_proxy_syntax_errors():
    result = SurgeParser().parse_result(
        '[Proxy]\nbad = ss, example.com, 8388, password="unterminated'
    )

    assert result.nodes == []
    assert len(result.issues) == 1
    assert result.issues[0].code == "parse.syntax"
    assert result.issues[0].node == "bad"
    assert "unterminated double quote" in result.issues[0].message


def test_surge_parser_vmess_aead():
    """Test parsing vmess-aead parameter"""
    conf = """
[Proxy]
vmess1 = vmess, server.example.com, 443, username=4189e3cc-b796-4c5d-85b7-45977ffa7a81, vmess-aead=true
vmess2 = vmess, server.example.com, 443, username=4189e3cc-b796-4c5d-85b7-45977ffa7a81, vmess-aead=false
vmess3 = vmess, server.example.com, 443, username=4189e3cc-b796-4c5d-85b7-45977ffa7a81
"""
    nodes = SurgeParser().parse(conf)
    assert len(nodes) == 3
    assert nodes[0].vmess_aead is True
    assert nodes[1].vmess_aead is False
    assert nodes[2].vmess_aead is False  # Default is False

    # Test emitter preserves vmess-aead parameter and does not output encrypt-method
    emitter = SurgeEmitter()
    output = emitter.emit([nodes[0]])
    assert "vmess-aead=true" in output
    assert "encrypt-method" not in output  # Should not output encrypt-method

    output2 = emitter.emit([nodes[1]])
    assert "vmess-aead=false" not in output2  # Should not output false
    assert "encrypt-method" not in output2  # Should not output encrypt-method

    output3 = emitter.emit([nodes[2]])
    assert "vmess-aead" not in output3  # Should not output if False
    assert "encrypt-method" not in output3  # Should not output encrypt-method


def test_surge_emitter_preserves_obfs_host_for_tls_mode():
    """Surge allows obfs-host for both supported simple-obfs modes."""
    from subio_v2.model.nodes import ShadowsocksNode, Protocol

    emitter = SurgeEmitter()

    # Test obfs=tls without host
    node1 = ShadowsocksNode(
        name="ss-tls",
        type=Protocol.SHADOWSOCKS,
        server="server",
        port=443,
        cipher="aes-256-gcm",
        password="password",
        plugin="obfs",
        plugin_opts={"mode": "tls"},
    )
    output1 = emitter.emit([node1])
    assert "obfs=tls" in output1
    assert "obfs-host" not in output1  # Should not output obfs-host for tls mode

    # Test obfs=tls with host
    node2 = ShadowsocksNode(
        name="ss-tls-host",
        type=Protocol.SHADOWSOCKS,
        server="server",
        port=443,
        cipher="aes-256-gcm",
        password="password",
        plugin="obfs",
        plugin_opts={"mode": "tls", "host": "bing.com"},
    )
    output2 = emitter.emit([node2])
    assert "obfs=tls" in output2
    assert "obfs-host=bing.com" in output2

    # Test obfs=http with host (should output host)
    node3 = ShadowsocksNode(
        name="ss-http-host",
        type=Protocol.SHADOWSOCKS,
        server="server",
        port=443,
        cipher="aes-256-gcm",
        password="password",
        plugin="obfs",
        plugin_opts={"mode": "http", "host": "bing.com"},
    )
    output3 = emitter.emit([node3])
    assert "obfs=http" in output3
    assert "obfs-host=bing.com" in output3  # Should output obfs-host for http mode


def test_surge_parser_and_emitter_preserve_quoted_alpn_and_common_options():
    result = SurgeParser().parse_result(
        """
[Proxy]
tuic = tuic-v5, example.com, 443, uuid=u, password=p, alpn="h3,h2", tfo=true, ip-version=prefer-v4, interface=en0, underlying-proxy=entry
"""
    )

    assert result.issues == []
    node = result.nodes[0]
    assert node.tls.alpn == ["h3", "h2"]
    assert node.tfo is True
    assert node.ip_version == "prefer-v4"
    assert node.interface_name == "en0"
    assert node.dialer_proxy == "entry"

    output = SurgeEmitter().emit(result.nodes)
    assert 'alpn="h3,h2"' in output
    assert "tfo=true" in output
    assert "ip-version=prefer-v4" in output
    assert "interface=en0" in output
    assert "underlying-proxy=entry" in output


def test_surge_udp_relay_is_emitted_only_for_opt_in_protocols():
    nodes = SurgeParser().parse(
        """
[Proxy]
http = http, example.com, 80
vmess = vmess, example.com, 443, username=u
trojan = trojan, example.com, 443, password=p
snell = snell, example.com, 443, psk=p, version=5, udp-relay=false
tuic = tuic-v5, example.com, 443, uuid=u, password=p, udp-relay=false
hysteria2 = hysteria2, example.com, 443, password=p
socks = socks5, example.com, 1080, udp-relay=true
ss = ss, example.com, 8388, encrypt-method=aes-256-gcm, password=p, udp-relay=true
"""
    )

    by_name = {node.name: node for node in nodes}
    assert by_name["http"].udp is False
    assert by_name["vmess"].udp is True
    assert by_name["trojan"].udp is True
    assert by_name["snell"].udp is True
    assert by_name["snell"].tls.enabled is False
    assert by_name["tuic"].udp is True
    assert by_name["hysteria2"].udp is True

    lines = {
        line.split(" = ", 1)[0]: line
        for line in SurgeEmitter().emit(nodes).splitlines()
        if " = " in line
    }
    for name in ("http", "vmess", "trojan", "snell", "tuic", "hysteria2"):
        assert "udp-relay" not in lines[name]
    assert "udp-relay=true" in lines["socks"]
    assert "udp-relay=true" in lines["ss"]


def test_surge_hysteria2_uses_current_obfs_parameter_names():
    result = SurgeParser().parse_result(
        """
[Proxy]
salamander = hysteria2, example.com, 443, password=p, salamander-password=secret-a
gecko = hysteria2, example.com, 443, password=p, gecko-password=secret-b
invalid = hysteria2, example.com, 443, password=p, salamander-password=a, gecko-password=b
"""
    )

    assert [(node.name, node.obfs, node.obfs_password) for node in result.nodes] == [
        ("salamander", "salamander", "secret-a"),
        ("gecko", "gecko", "secret-b"),
    ]
    assert [issue.node for issue in result.issues] == ["invalid"]

    output = SurgeEmitter().emit(result.nodes)
    assert "salamander-password=secret-a" in output
    assert "gecko-password=secret-b" in output
    assert "obfs=" not in output
    assert "obfs-password=" not in output


def test_surge_vmess_cipher_and_port_hopping_fields_round_trip():
    result = SurgeParser().parse_result(
        """
[Proxy]
default = vmess, example.com, 443, username=u
custom = vmess, example.com, 443, username=u, encrypt-method=auto
tuic = tuic-v5, example.com, 443, uuid=u, password=p, port-hopping="443,8443-8445", port-hopping-interval=30
hy2 = hysteria2, example.com, 443, password=p, port-hopping=443-445, port-hopping-interval=20
"""
    )

    assert result.issues == []
    by_name = {node.name: node for node in result.nodes}
    assert by_name["default"].cipher == "aes-128-gcm"
    assert by_name["custom"].cipher == "auto"
    assert by_name["tuic"].ports == "443,8443-8445"
    assert by_name["tuic"].hop_interval == 30
    assert by_name["hy2"].ports == "443-445"
    assert by_name["hy2"].hop_interval == 20

    output = SurgeEmitter().emit(result.nodes)
    default_line = next(
        line for line in output.splitlines() if line.startswith("default =")
    )
    custom_line = next(
        line for line in output.splitlines() if line.startswith("custom =")
    )
    assert "encrypt-method" not in default_line
    assert "encrypt-method=auto" in custom_line
    assert 'port-hopping="443,8443-8445"' in output
    assert "port-hopping-interval=30" in output


def test_surge_snell_versioned_fields_round_trip():
    nodes = SurgeParser().parse(
        """
[Proxy]
snell = snell, example.com, 443, psk=p, version=6, reuse=false, udp-port=8443, mode=quic
"""
    )

    node = nodes[0]
    assert node.reuse is False
    assert node.udp_port == 8443
    assert node.mode == "quic"
    output = SurgeEmitter().emit(nodes)
    assert "reuse=false" in output
    assert "udp-port=8443" in output
    assert "mode=quic" in output


def test_surge_emitter_ws_path_only_when_has_value():
    """Test that Surge emitter only outputs ws-path when it has a value"""
    from subio_v2.model.nodes import (
        TrojanNode,
        VmessNode,
        Protocol,
        TransportSettings,
        Network,
    )

    emitter = SurgeEmitter()

    # Test trojan with ws-path=None
    node1 = TrojanNode(
        name="trojan-ws",
        type=Protocol.TROJAN,
        server="server",
        port=443,
        password="example",
        transport=TransportSettings(network=Network.WS, path=None),
    )
    output1 = emitter.emit([node1])
    assert "ws=true" in output1
    assert "ws-path" not in output1  # Should not output ws-path when path is None

    # Test trojan with ws-path value
    node2 = TrojanNode(
        name="trojan-ws-path",
        type=Protocol.TROJAN,
        server="server",
        port=443,
        password="example",
        transport=TransportSettings(network=Network.WS, path="/path"),
    )
    output2 = emitter.emit([node2])
    assert "ws=true" in output2
    assert "ws-path=/path" in output2  # Should output ws-path when path has value

    # Test vmess with ws-path=None
    node3 = VmessNode(
        name="vmess-ws",
        type=Protocol.VMESS,
        server="server",
        port=443,
        uuid="test-uuid",
        transport=TransportSettings(network=Network.WS, path=None),
    )
    output3 = emitter.emit([node3])
    assert "ws=true" in output3
    assert "ws-path" not in output3  # Should not output ws-path when path is None

    # Test vmess with ws-path value
    node4 = VmessNode(
        name="vmess-ws-path",
        type=Protocol.VMESS,
        server="server",
        port=443,
        uuid="test-uuid",
        transport=TransportSettings(network=Network.WS, path="/ws-path"),
    )
    output4 = emitter.emit([node4])
    assert "ws=true" in output4
    assert "ws-path=/ws-path" in output4  # Should output ws-path when path has value


def test_surge_keystore_parse_and_emit():
    """Test parsing and emitting Surge Keystore section"""
    conf = """
[Proxy]
ssh1 = ssh, 1.1.1.1, 22, username=root, password=123
ssh2 = ssh, 1.1.1.1, 22, username=root, private-key=111

[Keystore]
111 = type = openssh-private-key, base64 = LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFNd0FBQUF0emMyZ3RaVwpReU5UVXhPUUFBQUNEZmFQald3d2lEU28vdlJaeFdleHRCa1gxeUg0dkVjYTV1c0JkZ2pCNGtqQUFBQUppTGVMak1pM2k0CnpBQUFBQXR6YzJndFpXUXlOVFV4T1FBQUFDRGZhUGpXd3dpRFNvL3ZSWnhXZXh0QmtYMXlINHZFY2E1dXNCZGdqQjRrakEKQUFBRUNETFc5bWtRMzJpc1hLZEVOdW52SFUwLzc2eVZ1TjIyU3NGSjU3UXVZUVBkOW8rTmJEQ0lOS2orOUZuRlo3RzBHUgpmWElmaThSeHJtNndGMkNNSGlTTUFBQUFGSE56YUhCeWIzaDVRSFIxYm01bGJDMXZibXg1QVE9PQotLS0tLUVORCBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K
"""
    parser = SurgeParser()
    nodes = parser.parse(conf)

    # Check parsing
    assert len(nodes) == 2
    ssh1 = [n for n in nodes if n.name == "ssh1"][0]
    ssh2 = [n for n in nodes if n.name == "ssh2"][0]
    assert ssh1.keystore_id is None
    assert ssh2.keystore_id == "111"
    assert "111" in parser.keystore
    assert parser.keystore["111"]["type"] == "openssh-private-key"
    assert "base64" in parser.keystore["111"]

    # Test emitter
    emitter = SurgeEmitter(keystore=parser.keystore)
    output = emitter.emit(nodes)

    # Check output
    assert "ssh1 = ssh, 1.1.1.1, 22, username=root, password=123" in output
    assert "ssh2 = ssh, 1.1.1.1, 22, username=root, private-key=111" in output
    assert "[Keystore]" in output
    assert "111 = type = openssh-private-key" in output
    assert "base64 = LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K" in output


def test_surge_parse_result_resources_rebuild_keystore_without_parser_state():
    result = SurgeParser().parse_result(
        """
[Proxy]
ssh = ssh, example.com, 22, username=root, private-key=key-id
[Keystore]
key-id = type = openssh-private-key, base64 = S0VZ
"""
    )
    resources = result.resources

    output = SurgeEmitter(keystore=resources["keystore"]).emit(result.nodes)

    assert "private-key=key-id" in output
    assert "[Keystore]" in output
    assert "key-id = type = openssh-private-key, base64 = S0VZ" in output
    assert resources["keystore"]["key-id"]["base64"] == "S0VZ"


def test_surge_keystore_parser_preserves_quoted_commas():
    result = SurgeParser().parse_result(
        """
[Keystore]
client-cert = type = p12, base64 = Q0VSVA==, password = "a,b"
"""
    )

    assert result.issues == []
    assert result.resources["keystore"]["client-cert"] == {
        "type": "p12",
        "base64": "Q0VSVA==",
        "password": "a,b",
    }


def test_surge_parser_resets_keystore_between_parse_calls():
    parser = SurgeParser()
    parser.parse(
        """
[Proxy]
first = ssh, first.example.com, 22, username=root, private-key=first-key
[Keystore]
first-key = type = openssh-private-key, base64 = S0VZLTE=
"""
    )
    assert set(parser.keystore) == {"first-key"}

    parser.parse(
        """
[Proxy]
second = ssh, second.example.com, 22, username=root, private-key=second-key
[Keystore]
second-key = type = openssh-private-key, base64 = S0VZLTI=
"""
    )

    assert set(parser.keystore) == {"second-key"}
    assert parser.keystore["second-key"]["base64"] == "S0VZLTI="


def test_surge_emitter_ssh_auto_keystore_from_clash():
    """Test that Surge emitter auto-generates keystore ID for SSH nodes from clash-like platforms"""
    from subio_v2.model.nodes import SSHNode, Protocol
    import base64

    # SSH node from clash-like platform (no keystore_id, but has private_key in raw format)
    # private_key is stored in raw format internally (without base64)
    raw_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAu3ZqXQyZTgqNTUxo8vRZxWextBkX1yH4vEca5usBdfjB4kjAAAIJ
iLeLjMi3i4zAAtzc2g1AAAAB3NzaC1yc2EAAAGBALt2al0MmU4KjU1MaPL0WcVnsbQZF9ch
+LxHGubrAXX4weJIwAACCSi3iyzIt4uMwALc3NoOQAAAAdzc2gtcnNhAAABgQC7dmpdDJlOC
o1NTGjy9FnFZ7G0GRfXIfi8Rxrm6wF2CMHiSMAABFhNzYaHByc3h5QHR9PQ==
-----END OPENSSH PRIVATE KEY-----"""

    node = SSHNode(
        name="ssh-from-clash",
        type=Protocol.SSH,
        server="server.example.com",
        port=22,
        username="root",
        private_key=raw_key,  # Raw format (without base64)
    )

    emitter = SurgeEmitter()
    output = emitter.emit([node])

    # Check that node is not modified
    assert node.keystore_id is None

    # Check output format
    assert "ssh-from-clash = ssh, server.example.com, 22, username=root" in output
    assert "private-key=" in output
    # private-key should be a short ID, not the full base64
    private_key_part = output.split("private-key=")[1].split(",")[0].split()[0]
    assert len(private_key_part) < 20  # Should be a short ID

    # Check Keystore section
    assert "[Keystore]" in output
    assert f"{private_key_part} = type = openssh-private-key" in output
    # Verify that the base64 in Keystore decodes to the original raw key
    keystore_section = output.split("[Keystore]")[1]
    base64_value = keystore_section.split("base64 = ")[1].strip().split("\n")[0]
    decoded = base64.b64decode(base64_value).decode("utf-8")
    assert decoded == raw_key

    # Test deterministic: same node should generate same keystore ID
    emitter2 = SurgeEmitter()
    output2 = emitter2.emit([node])
    private_key_part2 = output2.split("private-key=")[1].split(",")[0].split()[0]
    assert private_key_part == private_key_part2  # Should be deterministic


def test_surge_emitter_ssh_base64_encoding():
    """Test that Surge emitter correctly encodes raw private_key to base64 for Surge Keystore"""
    from subio_v2.model.nodes import SSHNode, Protocol
    import base64

    # private_key is stored in raw format internally (without base64)
    raw_key1 = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAu3ZqXQyZTgqNTUxo8vRZxWextBkX1yH4vEca5usBdfjB4kjAAAIJ
iLeLjMi3i4zAAtzc2g1AAAAB3NzaC1yc2EAAAGBALt2al0MmU4KjU1MaPL0WcVnsbQZF9ch
+LxHGubrAXX4weJIwAACCSi3iyzIt4uMwALc3NoOQAAAAdzc2gtcnNhAAABgQC7dmpdDJlOC
o1NTGjy9FnFZ7G0GRfXIfi8Rxrm6wF2CMHiSMAABFhNzYaHByc3h5QHR9PQ==
-----END OPENSSH PRIVATE KEY-----"""

    node1 = SSHNode(
        name="ssh-raw1",
        type=Protocol.SSH,
        server="server.example.com",
        port=22,
        username="root",
        private_key=raw_key1,  # Raw format
    )

    # Another raw key
    raw_key2 = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAu3ZqXQyZTgqNTUxo8vRZxWextBkX1yH4vEca5usBdfjB4kjAAAIJ
iLeLjMi3i4zAAtzc2g1AAAAB3NzaC1yc2EAAAGBALt2al0MmU4KjU1MaPL0WcVnsbQZF9ch
+LxHGubrAXX4weJIwAACCSi3iyzIt4uMwALc3NoOQAAAAdzc2gtcnNhAAABgQC7dmpdDJlOC
o1NTGjy9FnFZ7G0GRfXIfi8Rxrm6wF2CMHiSMAABFhNzYaHByc3h5QHR9PQ==
-----END OPENSSH PRIVATE KEY-----"""

    node2 = SSHNode(
        name="ssh-raw2",
        type=Protocol.SSH,
        server="server.example.com",
        port=22,
        username="root",
        private_key=raw_key2,  # Raw format
    )

    emitter = SurgeEmitter()
    output = emitter.emit([node1, node2])

    # Check that both keys are base64 encoded in Keystore
    assert "[Keystore]" in output

    # Verify that the base64 in Keystore decodes to the original raw keys
    keystore_section = output.split("[Keystore]")[1]
    base64_lines = [
        line for line in keystore_section.split("\n") if "base64 = " in line
    ]
    assert len(base64_lines) == 2

    for base64_line in base64_lines:
        base64_value = base64_line.split("base64 = ")[1].strip()
        decoded = base64.b64decode(base64_value).decode("utf-8")
        # Should decode to one of the raw keys
        assert decoded == raw_key1 or decoded == raw_key2
