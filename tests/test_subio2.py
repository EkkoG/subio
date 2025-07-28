"""SubIO2 测试用例"""
import pytest
from typing import List
import yaml
import json

from subio2.models import Node, NodeType, ProtocolConfig
from subio2.models.node import (
    CompositeNode, ShadowsocksProtocol, VmessProtocol, TrojanProtocol, VlessProtocol,
    HttpProtocol, Socks5Protocol, HysteriaProtocol, Hysteria2Protocol,
    TLSConfig, BasicAuth, Transport, WebSocketTransport, TransportType
)
from subio2.parsers.clash import ClashParser
from subio2.parsers.v2rayn import V2rayNParser
from subio2.parsers.surge import SurgeParser
from subio2.renderers.clash import ClashRenderer
from subio2.renderers.v2rayn import V2rayNRenderer
from subio2.renderers.surge import SurgeRenderer
from subio2.renderers.dae import DAERenderer
from subio2.filters import filter


class TestProtocolConfigs:
    """测试协议配置类"""
    
    def test_shadowsocks_config(self):
        """测试 Shadowsocks 配置"""
        config = ShadowsocksProtocol(
            cipher="aes-256-gcm",
            password="test123"
        )
        assert config.get_type() == NodeType.SHADOWSOCKS
        assert config.to_dict() == {
            'cipher': 'aes-256-gcm',
            'password': 'test123'
        }
    
    def test_vmess_config(self):
        """测试 VMess 配置"""
        config = VmessProtocol(
            uuid="550e8400-e29b-41d4-a716-446655440000",
            alter_id=64,
            cipher="auto"
        )
        assert config.get_type() == NodeType.VMESS
        data = config.to_dict()
        assert data['uuid'] == "550e8400-e29b-41d4-a716-446655440000"
        assert data['alterId'] == 64
    
    def test_trojan_config_validation(self):
        """测试 Trojan 配置验证"""
        config = TrojanProtocol(password="")
        with pytest.raises(ValueError, match="Password is required"):
            config.validate()


class TestCompositeNode:
    """测试组合节点"""
    
    def test_basic_node_creation(self):
        """测试基础节点创建"""
        node = CompositeNode(
            name="test-ss",
            server="example.com",
            port=8388,
            protocol=ShadowsocksProtocol(
                cipher="aes-256-gcm",
                password="test123"
            )
        )
        
        assert node.name == "test-ss"
        assert node.server == "example.com"
        assert node.port == 8388
        assert isinstance(node.protocol, ShadowsocksProtocol)
    
    def test_node_with_components(self):
        """测试带组件的节点"""
        node = CompositeNode(
            name="test-http",
            server="proxy.com",
            port=8080,
            protocol=HttpProtocol(),
            auth=BasicAuth(username="user", password="pass"),
            tls=TLSConfig(
                enabled=True,
                sni="custom.com",
                skip_cert_verify=True
            )
        )
        
        assert node.auth.username == "user"
        assert node.tls.sni == "custom.com"
        assert node.tls.skip_verify is True
    
    def test_node_to_dict(self):
        """测试节点转换为字典"""
        node = CompositeNode(
            name="test-vmess",
            server="example.com",
            port=443,
            protocol=VMessConfig(
                uuid="550e8400-e29b-41d4-a716-446655440000",
                alter_id=64
            ),
            transport=Transport(
                type=TransportType.WS,
                path="/ws",
                headers={"Host": "example.com"}
            )
        )
        
        data = node.to_dict()
        assert data['name'] == "test-vmess"
        assert data['type'] == "vmess"
        assert data['uuid'] == "550e8400-e29b-41d4-a716-446655440000"
        assert data['network'] == "ws"
        assert data['ws-opts']['path'] == "/ws"


class TestClashParser:
    """测试 Clash 解析器"""
    
    def test_parse_shadowsocks(self):
        """测试解析 Shadowsocks 节点"""
        content = """
        proxies:
          - name: ss-test
            type: ss
            server: example.com
            port: 8388
            cipher: aes-256-gcm
            password: test123
            udp: true
        """
        
        parser = ClashParser()
        nodes = parser.parse(content)
        
        assert len(nodes) == 1
        node = nodes[0]
        assert node.name == "ss-test"
        assert isinstance(node.protocol, ShadowsocksConfig)
        assert node.protocol.cipher == "aes-256-gcm"
        assert node.protocol.password == "test123"
    
    def test_parse_vmess_with_ws(self):
        """测试解析带 WebSocket 的 VMess 节点"""
        content = """
        proxies:
          - name: vmess-ws
            type: vmess
            server: example.com
            port: 443
            uuid: 550e8400-e29b-41d4-a716-446655440000
            alterId: 64
            cipher: auto
            tls: true
            network: ws
            ws-opts:
              path: /path
              headers:
                Host: example.com
        """
        
        parser = ClashParser()
        nodes = parser.parse(content)
        
        assert len(nodes) == 1
        node = nodes[0]
        assert node.name == "vmess-ws"
        assert node.transport.type == TransportType.WS
        assert node.transport.path == "/path"
        assert node.transport.headers["Host"] == "example.com"
        assert node.tls.enabled is True
    
    def test_parse_http_with_auth(self):
        """测试解析带认证的 HTTP 节点"""
        content = """
        proxies:
          - name: http-auth
            type: http
            server: proxy.com
            port: 8080
            username: user
            password: pass
            tls: true
            skip-cert-verify: true
        """
        
        parser = ClashParser()
        nodes = parser.parse(content)
        
        assert len(nodes) == 1
        node = nodes[0]
        assert node.auth.username == "user"
        assert node.auth.password == "pass"
        assert node.tls.skip_verify is True


class TestV2rayNParser:
    """测试 V2rayN 解析器"""
    
    def test_parse_ss_url(self):
        """测试解析 Shadowsocks URL"""
        # ss://YWVzLTI1Ni1nY206dGVzdDEyMw@example.com:8388#ss-test
        url = "ss://YWVzLTI1Ni1nY206dGVzdDEyMw@example.com:8388#ss-test"
        
        parser = V2rayNParser()
        nodes = parser.parse(url)
        
        assert len(nodes) == 1
        node = nodes[0]
        assert node.name == "ss-test"
        assert node.server == "example.com"
        assert node.port == 8388
        assert isinstance(node.protocol, ShadowsocksConfig)
    
    def test_parse_trojan_url(self):
        """测试解析 Trojan URL"""
        url = "trojan://password123@example.com:443?sni=custom.com&allowInsecure=1#trojan-test"
        
        parser = V2rayNParser()
        nodes = parser.parse(url)
        
        assert len(nodes) == 1
        node = nodes[0]
        assert node.name == "trojan-test"
        assert isinstance(node.protocol, TrojanConfig)
        assert node.protocol.password == "password123"
        assert node.tls.sni == "custom.com"
        assert node.tls.skip_verify is True


class TestRenderers:
    """测试渲染器"""
    
    def test_clash_renderer(self):
        """测试 Clash 渲染器"""
        nodes = [
            CompositeNode(
                name="test-ss",
                server="example.com",
                port=8388,
                protocol=ShadowsocksConfig(
                    cipher="aes-256-gcm",
                    password="test123"
                )
            )
        ]
        
        renderer = ClashRenderer()
        output = renderer.render(nodes, None, {})
        
        # 解析输出的 YAML
        data = yaml.safe_load(output)
        assert 'proxies' in data
        assert len(data['proxies']) == 1
        assert data['proxies'][0]['name'] == "test-ss"
        assert data['proxies'][0]['type'] == "ss"
    
    def test_v2rayn_renderer(self):
        """测试 V2rayN 渲染器"""
        nodes = [
            CompositeNode(
                name="test-vmess",
                server="example.com",
                port=443,
                protocol=VMessConfig(
                    uuid="550e8400-e29b-41d4-a716-446655440000",
                    alter_id=64
                )
            )
        ]
        
        renderer = V2rayNRenderer()
        output = renderer.render(nodes, None, {})
        
        # V2rayN 输出应该是 base64 编码的 URL
        assert output.startswith("vmess://")
    
    def test_surge_renderer(self):
        """测试 Surge 渲染器"""
        nodes = [
            CompositeNode(
                name="test-http",
                server="proxy.com",
                port=8080,
                protocol=HTTPConfig(),
                auth=BasicAuth(username="user", password="pass")
            )
        ]
        
        renderer = SurgeRenderer()
        output = renderer.render(nodes, None, {})
        
        assert "[Proxy]" in output
        assert "test-http = http, proxy.com, 8080, user, pass" in output


class TestFilters:
    """测试过滤器功能"""
    
    def test_hk_filter(self):
        """测试香港节点过滤器"""
        nodes = [
            CompositeNode(name="HK-01", server="hk1.com", port=443, 
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test")),
            CompositeNode(name="US-01", server="us1.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test")),
            CompositeNode(name="香港节点", server="hk2.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test"))
        ]
        
        filtered = filter.hk_filter(nodes)
        assert len(filtered) == 2
        assert all("HK" in node.name or "香港" in node.name for node in filtered)
    
    def test_keyword_filter(self):
        """测试关键词过滤器"""
        nodes = [
            CompositeNode(name="Premium-HK", server="hk1.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test")),
            CompositeNode(name="Free-US", server="us1.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test")),
            CompositeNode(name="Premium-JP", server="jp1.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test"))
        ]
        
        filtered = filter.keyWord_filter(nodes, "Premium")
        assert len(filtered) == 2
        assert all("Premium" in node.name for node in filtered)
    
    def test_combine_filter(self):
        """测试组合过滤器"""
        nodes = [
            CompositeNode(name="Premium-HK-01", server="hk1.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test")),
            CompositeNode(name="Free-HK-01", server="hk2.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test")),
            CompositeNode(name="Premium-US-01", server="us1.com", port=443,
                         protocol=ShadowsocksConfig(cipher="aes-256-gcm", password="test"))
        ]
        
        # 组合 HK 过滤器和关键词过滤器
        filtered = filter.combine(nodes, filter.hk_filter, filter.keyWord_filter, None, "Premium")
        assert len(filtered) == 1
        assert filtered[0].name == "Premium-HK-01"


class TestIntegration:
    """集成测试"""
    
    def test_clash_to_v2rayn(self):
        """测试 Clash 格式转换为 V2rayN"""
        clash_content = """
        proxies:
          - name: test-vmess
            type: vmess
            server: example.com
            port: 443
            uuid: 550e8400-e29b-41d4-a716-446655440000
            alterId: 64
            cipher: auto
            tls: true
        """
        
        # 解析 Clash 格式
        parser = ClashParser()
        nodes = parser.parse(clash_content)
        
        # 渲染为 V2rayN 格式
        renderer = V2rayNRenderer()
        output = renderer.render(nodes, None, {})
        
        # 验证输出
        assert output.startswith("vmess://")
        
        # 再次解析 V2rayN 格式验证往返转换
        parser2 = V2rayNParser()
        nodes2 = parser2.parse(output)
        
        assert len(nodes2) == 1
        assert nodes2[0].name == nodes[0].name
        assert nodes2[0].server == nodes[0].server
    
    def test_complex_node_conversion(self):
        """测试复杂节点的转换"""
        # 创建一个复杂的节点
        node = CompositeNode(
            name="complex-vmess",
            server="example.com",
            port=443,
            protocol=VMessConfig(
                uuid="550e8400-e29b-41d4-a716-446655440000",
                alter_id=64,
                cipher="auto"
            ),
            tls=TLSConfig(
                enabled=True,
                sni="custom.com",
                skip_verify=True,
                fingerprint="chrome"
            ),
            transport=Transport(
                type=TransportType.WS,
                path="/ws",
                headers={"Host": "example.com"},
                early_data_header="Sec-WebSocket-Protocol",
                max_early_data=2048
            )
        )
        
        # 测试转换为字典
        data = node.to_dict()
        assert data['tls'] is True
        assert data['sni'] == "custom.com"
        assert data['network'] == "ws"
        assert data['ws-opts']['path'] == "/ws"
        
        # 测试渲染为 Clash 格式
        renderer = ClashRenderer()
        output = renderer.render([node], None, {})
        
        # 验证输出包含所有必要字段
        assert "complex-vmess" in output
        assert "custom.com" in output
        assert "/ws" in output


class TestEdgeCases:
    """边缘情况测试"""
    
    def test_empty_input(self):
        """测试空输入"""
        parser = ClashParser()
        nodes = parser.parse("")
        assert nodes == []
        
        nodes = parser.parse("proxies: []")
        assert nodes == []
    
    def test_invalid_node_type(self):
        """测试无效的节点类型"""
        content = """
        proxies:
          - name: invalid
            type: unknown
            server: example.com
            port: 443
        """
        
        parser = ClashParser()
        nodes = parser.parse(content)
        assert len(nodes) == 0  # 应该跳过无效节点
    
    def test_missing_required_fields(self):
        """测试缺少必需字段"""
        content = """
        proxies:
          - name: incomplete
            type: ss
            server: example.com
            # 缺少 port, cipher, password
        """
        
        parser = ClashParser()
        nodes = parser.parse(content)
        assert len(nodes) == 0  # 应该跳过不完整的节点
    
    def test_special_characters_in_name(self):
        """测试名称中的特殊字符"""
        node = CompositeNode(
            name="测试节点 | 香港 #01 (Premium)",
            server="hk.example.com",
            port=443,
            protocol=TrojanConfig(password="test123")
        )
        
        # 测试过滤器能正确处理特殊字符
        filtered = filter.hk_filter([node])
        assert len(filtered) == 1
        
        # 测试渲染器能正确处理特殊字符
        renderer = ClashRenderer()
        output = renderer.render([node], None, {})
        assert "测试节点 | 香港 #01 (Premium)" in output


class TestNewProtocolSupport:
    """测试新协议支持的示例"""
    
    def test_wireguard_protocol(self):
        """测试 WireGuard 协议（示例）"""
        # 这是一个示例，展示如何测试新添加的协议
        # 实际实现时需要先添加 WireGuardConfig 类
        
        # 创建 WireGuard 配置
        # config = WireGuardConfig(
        #     private_key="private_key_base64",
        #     public_key="public_key_base64",
        #     preshared_key="preshared_key_base64"
        # )
        
        # 创建节点
        # node = CompositeNode(
        #     name="wg-test",
        #     server="wg.example.com",
        #     port=51820,
        #     protocol=config
        # )
        
        # 测试转换和渲染
        # assert node.protocol.get_type() == NodeType.WIREGUARD
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])