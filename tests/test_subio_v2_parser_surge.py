import pytest
from subio_v2.parser.surge import SurgeParser
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.model.nodes import Protocol


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


def test_surge_emitter_obfs_tls_no_host():
    """Test that Surge emitter does not output obfs-host when obfs mode is tls"""
    from subio_v2.model.nodes import ShadowsocksNode, Protocol
    
    emitter = SurgeEmitter()
    
    # Test obfs=tls without host
    node1 = ShadowsocksNode(
        name='ss-tls',
        type=Protocol.SHADOWSOCKS,
        server='server',
        port=443,
        cipher='aes-256-gcm',
        password='password',
        plugin='obfs',
        plugin_opts={'mode': 'tls'}
    )
    output1 = emitter.emit([node1])
    assert "obfs=tls" in output1
    assert "obfs-host" not in output1  # Should not output obfs-host for tls mode
    
    # Test obfs=tls with host (should ignore host)
    node2 = ShadowsocksNode(
        name='ss-tls-host',
        type=Protocol.SHADOWSOCKS,
        server='server',
        port=443,
        cipher='aes-256-gcm',
        password='password',
        plugin='obfs',
        plugin_opts={'mode': 'tls', 'host': 'bing.com'}
    )
    output2 = emitter.emit([node2])
    assert "obfs=tls" in output2
    assert "obfs-host" not in output2  # Should not output obfs-host for tls mode
    
    # Test obfs=http with host (should output host)
    node3 = ShadowsocksNode(
        name='ss-http-host',
        type=Protocol.SHADOWSOCKS,
        server='server',
        port=443,
        cipher='aes-256-gcm',
        password='password',
        plugin='obfs',
        plugin_opts={'mode': 'http', 'host': 'bing.com'}
    )
    output3 = emitter.emit([node3])
    assert "obfs=http" in output3
    assert "obfs-host=bing.com" in output3  # Should output obfs-host for http mode


def test_surge_emitter_ws_path_only_when_has_value():
    """Test that Surge emitter only outputs ws-path when it has a value"""
    from subio_v2.model.nodes import TrojanNode, VmessNode, Protocol, TransportSettings, Network
    
    emitter = SurgeEmitter()
    
    # Test trojan with ws-path=None
    node1 = TrojanNode(
        name='trojan-ws',
        type=Protocol.TROJAN,
        server='server',
        port=443,
        password='example',
        transport=TransportSettings(network=Network.WS, path=None)
    )
    output1 = emitter.emit([node1])
    assert "ws=true" in output1
    assert "ws-path" not in output1  # Should not output ws-path when path is None
    
    # Test trojan with ws-path value
    node2 = TrojanNode(
        name='trojan-ws-path',
        type=Protocol.TROJAN,
        server='server',
        port=443,
        password='example',
        transport=TransportSettings(network=Network.WS, path='/path')
    )
    output2 = emitter.emit([node2])
    assert "ws=true" in output2
    assert "ws-path=/path" in output2  # Should output ws-path when path has value
    
    # Test vmess with ws-path=None
    node3 = VmessNode(
        name='vmess-ws',
        type=Protocol.VMESS,
        server='server',
        port=443,
        uuid='test-uuid',
        transport=TransportSettings(network=Network.WS, path=None)
    )
    output3 = emitter.emit([node3])
    assert "ws=true" in output3
    assert "ws-path" not in output3  # Should not output ws-path when path is None
    
    # Test vmess with ws-path value
    node4 = VmessNode(
        name='vmess-ws-path',
        type=Protocol.VMESS,
        server='server',
        port=443,
        uuid='test-uuid',
        transport=TransportSettings(network=Network.WS, path='/ws-path')
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


def test_surge_emitter_ssh_auto_keystore_from_clash():
    """Test that Surge emitter auto-generates keystore ID for SSH nodes from clash-like platforms"""
    from subio_v2.model.nodes import SSHNode, Protocol
    import base64
    
    # SSH node from clash-like platform (no keystore_id, but has private_key in raw format)
    # private_key is stored in raw format internally (without base64)
    raw_key = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAu3ZqXQyZTgqNTUxo8vRZxWextBkX1yH4vEca5usBdfjB4kjAAAIJ
iLeLjMi3i4zAAtzc2g1AAAAB3NzaC1yc2EAAAGBALt2al0MmU4KjU1MaPL0WcVnsbQZF9ch
+LxHGubrAXX4weJIwAACCSi3iyzIt4uMwALc3NoOQAAAAdzc2gtcnNhAAABgQC7dmpdDJlOC
o1NTGjy9FnFZ7G0GRfXIfi8Rxrm6wF2CMHiSMAABFhNzYaHByc3h5QHR9PQ==
-----END OPENSSH PRIVATE KEY-----'''
    
    node = SSHNode(
        name='ssh-from-clash',
        type=Protocol.SSH,
        server='server.example.com',
        port=22,
        username='root',
        private_key=raw_key  # Raw format (without base64)
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
    decoded = base64.b64decode(base64_value).decode('utf-8')
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
    raw_key1 = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAu3ZqXQyZTgqNTUxo8vRZxWextBkX1yH4vEca5usBdfjB4kjAAAIJ
iLeLjMi3i4zAAtzc2g1AAAAB3NzaC1yc2EAAAGBALt2al0MmU4KjU1MaPL0WcVnsbQZF9ch
+LxHGubrAXX4weJIwAACCSi3iyzIt4uMwALc3NoOQAAAAdzc2gtcnNhAAABgQC7dmpdDJlOC
o1NTGjy9FnFZ7G0GRfXIfi8Rxrm6wF2CMHiSMAABFhNzYaHByc3h5QHR9PQ==
-----END OPENSSH PRIVATE KEY-----'''
    
    node1 = SSHNode(
        name='ssh-raw1',
        type=Protocol.SSH,
        server='server.example.com',
        port=22,
        username='root',
        private_key=raw_key1  # Raw format
    )
    
    # Another raw key
    raw_key2 = '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAu3ZqXQyZTgqNTUxo8vRZxWextBkX1yH4vEca5usBdfjB4kjAAAIJ
iLeLjMi3i4zAAtzc2g1AAAAB3NzaC1yc2EAAAGBALt2al0MmU4KjU1MaPL0WcVnsbQZF9ch
+LxHGubrAXX4weJIwAACCSi3iyzIt4uMwALc3NoOQAAAAdzc2gtcnNhAAABgQC7dmpdDJlOC
o1NTGjy9FnFZ7G0GRfXIfi8Rxrm6wF2CMHiSMAABFhNzYaHByc3h5QHR9PQ==
-----END OPENSSH PRIVATE KEY-----'''
    
    node2 = SSHNode(
        name='ssh-raw2',
        type=Protocol.SSH,
        server='server.example.com',
        port=22,
        username='root',
        private_key=raw_key2  # Raw format
    )
    
    emitter = SurgeEmitter()
    output = emitter.emit([node1, node2])
    
    # Check that both keys are base64 encoded in Keystore
    assert "[Keystore]" in output
    
    # Verify that the base64 in Keystore decodes to the original raw keys
    keystore_section = output.split("[Keystore]")[1]
    base64_lines = [line for line in keystore_section.split('\n') if 'base64 = ' in line]
    assert len(base64_lines) == 2
    
    for base64_line in base64_lines:
        base64_value = base64_line.split('base64 = ')[1].strip()
        decoded = base64.b64decode(base64_value).decode('utf-8')
        # Should decode to one of the raw keys
        assert decoded == raw_key1 or decoded == raw_key2
