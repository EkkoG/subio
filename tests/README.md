# SubIO2 测试文档

本目录包含 SubIO2 的测试用例和测试文档。

## 测试文件说明

### test_basic.py
基础功能测试，验证核心模块的导入和基本功能：
- 模块导入测试
- 节点创建测试
- 解析器基础功能测试
- 渲染器基础功能测试
- 过滤器导入测试

### test_subio2.py
完整的单元测试套件（需要进一步完善）：
- 协议配置类测试
- 组合节点测试
- 解析器详细测试
- 渲染器详细测试
- 过滤器功能测试
- 集成测试

## 运行测试

### 安装测试依赖
```bash
uv sync --dev
```

### 运行基础测试
```bash
uv run pytest tests/test_basic.py -v -s
```

### 运行所有测试
```bash
uv run pytest tests/ -v
```

### 运行特定测试
```bash
uv run pytest tests/test_basic.py::test_node_creation -v
```

## 测试覆盖率

要生成测试覆盖率报告：
```bash
uv run pytest tests/ --cov=subio2 --cov-report=html
```

## 手动测试

### 端到端测试
```bash
# 在项目根目录运行
cd example
uv run subio2

# 检查输出
ls dist-subio2/
```

### 对比测试
```bash
# 运行 v1 和 v2
uv run subio && uv run subio2

# 对比输出
diff dist/ dist-subio2/
```

## 测试数据

测试使用 `example/` 目录下的配置和数据：
- `config.yaml`: 主配置文件
- `example.yaml`: 示例节点数据
- `dist/`: v1 输出目录
- `dist-subio2/`: v2 输出目录

## 测试策略

### 单元测试
- 每个协议配置类的测试
- 组件类（BasicAuth, TLSConfig, Transport）的测试
- 解析器和渲染器的独立测试

### 集成测试
- 完整的解析-渲染流程测试
- 多种格式之间的转换测试
- 过滤器组合功能测试

### 边缘情况测试
- 空输入处理
- 无效数据处理
- 缺失字段处理
- 特殊字符处理

### 性能测试
- 大量节点处理性能
- 复杂过滤器性能
- 内存使用测试

## 添加新测试

当添加新协议或新平台时，需要添加相应的测试：

### 新协议测试模板
```python
def test_new_protocol_config():
    """测试新协议配置"""
    config = NewProtocolConfig(
        required_param="value",
        optional_param="optional"
    )
    assert config.get_type() == NodeType.NEW_PROTOCOL
    assert config.validate() is None  # 无异常
    
def test_new_protocol_parsing():
    """测试新协议解析"""
    content = """
    proxies:
      - name: test-new
        type: newprotocol
        server: example.com
        port: 443
        required_param: value
    """
    parser = ClashParser()
    nodes = parser.parse(content)
    assert len(nodes) == 1
    assert isinstance(nodes[0].protocol, NewProtocolConfig)

def test_new_protocol_rendering():
    """测试新协议渲染"""
    node = CompositeNode(
        name="test-new",
        server="example.com",
        port=443,
        protocol=NewProtocolConfig(required_param="value")
    )
    renderer = ClashRenderer()
    output = renderer.render([node], None, {})
    assert "newprotocol" in output
```

### 新平台测试模板
```python
def test_new_platform_renderer():
    """测试新平台渲染器"""
    nodes = [create_test_node()]
    renderer = NewPlatformRenderer()
    output = renderer.render(nodes, None, {})
    
    # 验证平台特定的格式
    assert output.startswith("# New Platform Config")
    assert "test-node" in output

def test_new_platform_parser():
    """测试新平台解析器"""
    content = "platform_specific_format_content"
    parser = NewPlatformParser()
    nodes = parser.parse(content)
    assert len(nodes) > 0
```

## 持续集成

建议在 CI/CD 流程中包含：
1. 所有测试的执行
2. 测试覆盖率检查
3. 代码质量检查
4. 端到端功能验证

## 调试指南

### 调试失败的测试
```bash
# 详细输出
uv run pytest tests/test_basic.py -v -s --tb=long

# 进入调试器
uv run pytest tests/test_basic.py --pdb

# 只运行失败的测试
uv run pytest tests/test_basic.py --lf
```

### 查看测试覆盖率
```bash
uv run pytest tests/ --cov=subio2 --cov-report=term-missing
```

这将显示哪些代码行没有被测试覆盖。