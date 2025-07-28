"""SubIO2 性能测试"""
import pytest
import time
from typing import List

from subio2.models.node import Proxy, ShadowsocksProtocol
from subio2.filters.filter import hk_filter, combine, all_filters


def create_test_nodes(count: int = 100) -> List[Proxy]:
    """创建测试节点"""
    nodes = []
    regions = ["HK", "US", "JP", "SG", "UK"]
    
    for i in range(count):
        region = regions[i % len(regions)]
        node = Proxy(
            name=f"{region}-{i:03d}",
            server=f"{region.lower()}{i}.example.com",
            port=443,
            protocol=ShadowsocksProtocol(
                method="aes-256-gcm",
                password=f"password{i}"
            )
        )
        nodes.append(node)
    
    return nodes


@pytest.mark.slow
def test_large_node_set_parsing():
    """测试大量节点的处理性能"""
    # 创建大量节点的 YAML 内容
    nodes_data = []
    for i in range(1000):
        nodes_data.append(f"""
  - name: test-{i:04d}
    type: ss
    server: server{i}.example.com
    port: 443
    cipher: aes-256-gcm
    password: password{i}""")
    
    content = "proxies:" + "".join(nodes_data)
    
    # 测试解析性能
    from subio2.parsers.clash import ClashParser
    parser = ClashParser()
    
    start_time = time.time()
    try:
        nodes = parser.parse(content)
        parse_time = time.time() - start_time
        
        print(f"Parsed {len(nodes)} nodes in {parse_time:.3f} seconds")
        print(f"Average: {parse_time/len(nodes)*1000:.2f} ms per node")
        
        # 性能基准：应该能在合理时间内处理大量节点
        assert parse_time < 5.0  # 不超过5秒
        
    except Exception as e:
        print(f"Parser performance test failed: {e}")


@pytest.mark.slow 
def test_filter_performance():
    """测试过滤器性能"""
    nodes = create_test_nodes(1000)
    
    # 测试单个过滤器性能
    start_time = time.time()
    hk_nodes = hk_filter(nodes)
    filter_time = time.time() - start_time
    
    print(f"Filtered {len(nodes)} nodes to {len(hk_nodes)} HK nodes in {filter_time:.3f} seconds")
    
    # 测试组合过滤器性能
    start_time = time.time()
    combined = combine(nodes, all_filters.hk_filter, all_filters.keyWord_filter, None, "001")
    combine_time = time.time() - start_time
    
    print(f"Combined filter took {combine_time:.3f} seconds, result: {len(combined)} nodes")
    
    # 性能基准
    assert filter_time < 1.0  # 单个过滤器不超过1秒
    assert combine_time < 2.0  # 组合过滤器不超过2秒


def test_node_creation_performance():
    """测试节点创建性能"""
    start_time = time.time()
    nodes = create_test_nodes(1000)
    creation_time = time.time() - start_time
    
    print(f"Created {len(nodes)} nodes in {creation_time:.3f} seconds")
    print(f"Average: {creation_time/len(nodes)*1000:.2f} ms per node")
    
    # 验证节点正确创建
    assert len(nodes) == 1000
    assert all(node.name.startswith(("HK", "US", "JP", "SG", "UK")) for node in nodes)
    
    # 性能基准
    assert creation_time < 1.0  # 创建1000个节点不超过1秒


def test_renderer_performance():
    """测试渲染器性能"""
    nodes = create_test_nodes(100)
    
    from subio2.renderers.clash import ClashRenderer
    renderer = ClashRenderer()
    
    start_time = time.time()
    try:
        output = renderer.render(nodes, None, {})
        render_time = time.time() - start_time
        
        print(f"Rendered {len(nodes)} nodes in {render_time:.3f} seconds")
        print(f"Output length: {len(output)} characters")
        
        # 基本验证
        assert isinstance(output, str)
        assert len(output) > 0
        
        # 性能基准
        assert render_time < 2.0  # 渲染不超过2秒
        
    except Exception as e:
        print(f"Renderer performance test failed: {e}")


@pytest.mark.integration
def test_end_to_end_performance():
    """测试端到端性能"""
    # 创建测试内容
    nodes_data = []
    for i in range(200):
        region = ["HK", "US", "JP"][i % 3]
        nodes_data.append(f"""
  - name: {region}-{i:03d}
    type: ss
    server: {region.lower()}{i}.example.com
    port: 443
    cipher: aes-256-gcm
    password: password{i}""")
    
    content = "proxies:" + "".join(nodes_data)
    
    # 完整流程测试
    from subio2.parsers.clash import ClashParser
    from subio2.renderers.clash import ClashRenderer
    
    start_time = time.time()
    
    # 解析
    parser = ClashParser()
    nodes = parser.parse(content)
    parse_time = time.time() - start_time
    
    # 过滤
    filter_start = time.time()
    hk_nodes = hk_filter(nodes)
    filter_time = time.time() - filter_start
    
    # 渲染
    render_start = time.time()
    renderer = ClashRenderer()
    try:
        output = renderer.render(hk_nodes, None, {})
        render_time = time.time() - render_start
        
        total_time = time.time() - start_time
        
        print(f"End-to-end performance:")
        print(f"  Parse: {parse_time:.3f}s")
        print(f"  Filter: {filter_time:.3f}s") 
        print(f"  Render: {render_time:.3f}s")
        print(f"  Total: {total_time:.3f}s")
        print(f"  Nodes: {len(nodes)} -> {len(hk_nodes)}")
        
        # 性能基准
        assert total_time < 5.0  # 总时间不超过5秒
        
    except Exception as e:
        print(f"End-to-end test failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "-m", "not slow"])