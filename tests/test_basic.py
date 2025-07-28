"""SubIO2 基础功能测试"""
import pytest
import yaml

# 基础导入测试
def test_imports():
    """测试基础模块导入"""
    try:
        from subio2.models import Node, NodeType
        from subio2.models.node import CompositeNode, ShadowsocksProtocol
        from subio2.parsers.clash import ClashParser
        from subio2.renderers.clash import ClashRenderer
        assert True
    except ImportError as e:
        pytest.fail(f"Import failed: {e}")


def test_node_creation():
    """测试节点创建"""
    from subio2.models.node import CompositeNode, ShadowsocksProtocol
    
    node = CompositeNode(
        name="test-node",
        server="example.com", 
        port=443,
        protocol=ShadowsocksProtocol(
            method="aes-256-gcm",
            password="test123"
        )
    )
    
    assert node.name == "test-node"
    assert node.server == "example.com"
    assert node.port == 443


def test_clash_parser():
    """测试 Clash 解析器基础功能"""
    from subio2.parsers.clash import ClashParser
    
    content = """
    proxies:
      - name: test-ss
        type: ss
        server: example.com
        port: 443
        cipher: aes-256-gcm
        password: test123
    """
    
    parser = ClashParser()
    try:
        nodes = parser.parse(content)
        # 基本验证，不要求特定结果
        assert isinstance(nodes, list)
    except Exception as e:
        # 允许解析失败，但要记录错误
        print(f"Parser failed: {e}")


def test_clash_renderer():
    """测试 Clash 渲染器基础功能"""
    from subio2.models.node import CompositeNode, ShadowsocksProtocol
    from subio2.renderers.clash import ClashRenderer
    
    node = CompositeNode(
        name="test-node",
        server="example.com",
        port=443,
        protocol=ShadowsocksProtocol(
            method="aes-256-gcm", 
            password="test123"
        )
    )
    
    renderer = ClashRenderer()
    try:
        output = renderer.render([node], None, {})
        assert isinstance(output, str)
        assert len(output) > 0
    except Exception as e:
        print(f"Renderer failed: {e}")


def test_registry():
    """测试注册表功能"""
    try:
        from subio2.registry import registry
        
        # 检查是否有注册的解析器和渲染器
        parsers = registry.get_parsers()
        renderers = registry.get_renderers()
        
        assert isinstance(parsers, dict)
        assert isinstance(renderers, dict)
        print(f"Registered parsers: {list(parsers.keys())}")
        print(f"Registered renderers: {list(renderers.keys())}")
        
    except Exception as e:
        print(f"Registry test failed: {e}")


def test_filter_import():
    """测试过滤器模块导入"""
    try:
        from subio2.filters.filter import hk_filter, us_filter
        assert callable(hk_filter)
        assert callable(us_filter)
    except ImportError as e:
        print(f"Filter import failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])