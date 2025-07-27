# SubIO2 开发文档

SubIO2 是一个基于插件架构的代理配置转换工具，采用模块化设计和组合模式，支持多种代理协议和平台。本文档介绍如何扩展 SubIO2 以支持新的协议和平台。

## 架构概述

SubIO2 采用以下核心设计模式：

1. **模块化架构**：每个平台（解析器/渲染器）是一个独立模块，每个协议在单独文件中实现
2. **插件架构**：通过注册表模式和装饰器自动注册解析器和渲染器
3. **组合模式**：使用 `CompositeNode` 统一表示所有协议节点
4. **策略模式**：不同协议通过 `ProtocolConfig` 子类实现特定行为
5. **模板引擎**：使用 Jinja2 模板渲染输出格式

## 目录结构

```
src/subio2/
├── parsers/          # 解析器模块
│   ├── clash/        # Clash 解析器
│   │   ├── base.py   # 基础解析器类
│   │   └── protocols/# 协议特定解析器
│   │       ├── shadowsocks.py
│   │       ├── vmess.py
│   │       └── ...
│   ├── v2rayn/      # V2rayN 解析器
│   └── ...
├── renderers/        # 渲染器模块
│   ├── clash/        # Clash 渲染器
│   │   ├── base.py   # 基础渲染器类
│   │   └── protocols/# 协议特定渲染器
│   └── ...
└── models/           # 数据模型
    └── node_composite.py  # 组合节点模型
```

## 添加新协议

### 1. 定义协议配置类

在 `src/subio2/models/node_composite.py` 中创建新的协议配置类：

```python
@dataclass
class NewProtocolConfig(ProtocolConfig):
    """新协议的配置类"""
    # 定义协议特有的字段
    encryption: str
    special_param: Optional[str] = None
    
    def get_type(self) -> NodeType:
        return NodeType.NEWPROTOCOL  # 需要在 NodeType 中添加
    
    def validate(self) -> None:
        """验证配置的有效性"""
        if not self.encryption:
            raise ValueError("Encryption is required for NewProtocol")
```

### 2. 更新 NodeType 枚举

在 `src/subio2/models/node_composite.py` 中添加新的节点类型：

```python
class NodeType(Enum):
    # ... 现有类型 ...
    NEWPROTOCOL = "newprotocol"
```

### 3. 为每个平台添加协议解析器

#### 3.1 Clash 解析器

创建 `src/subio2/parsers/clash/protocols/newprotocol.py`：

```python
from typing import Dict, Any, Optional
from ....models.node_composite import CompositeNode, NewProtocolConfig
from .registry import protocol_registry

@protocol_registry.register('newprotocol')
def parse_newprotocol(proxy: Dict[str, Any]) -> Optional[CompositeNode]:
    """解析 NewProtocol 配置"""
    protocol = NewProtocolConfig(
        encryption=proxy.get('encryption', 'default'),
        special_param=proxy.get('special-param')
    )
    
    node = CompositeNode(
        name=proxy['name'],
        server=proxy['server'],
        port=proxy['port'],
        protocol=protocol
    )
    
    # 处理通用字段
    if proxy.get('tls'):
        node.tls = TLSConfig(
            enabled=True,
            skip_cert_verify=proxy.get('skip-cert-verify', False)
        )
    
    return node
```

#### 3.2 V2rayN 解析器

如果新协议支持 V2rayN URL 格式，创建 `src/subio2/parsers/v2rayn/protocols/newprotocol.py`：

```python
from typing import Optional
from urllib.parse import urlparse, parse_qs
from ....models.node_composite import CompositeNode, NewProtocolConfig

def parse(url: str) -> Optional[CompositeNode]:
    """解析 newprotocol:// URL"""
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'newprotocol':
            return None
        
        # 解析 URL 组件
        # newprotocol://encryption:password@server:port?param=value#name
        
        # 实现解析逻辑
        return CompositeNode(...)
    except Exception:
        return None
```

### 4. 为每个平台添加协议渲染器

#### 4.1 Clash 渲染器

创建 `src/subio2/renderers/clash/protocols/newprotocol.py`：

```python
from typing import Dict, Any
from ....models.node_composite import CompositeNode, NewProtocolConfig
from .registry import clash_protocol_registry

@clash_protocol_registry.register('newprotocol')
def render_newprotocol(node: CompositeNode) -> Dict[str, Any]:
    """渲染 NewProtocol 节点为 Clash 格式"""
    if not isinstance(node.protocol, NewProtocolConfig):
        return {}
    
    result = {
        'name': node.name,
        'type': 'newprotocol',
        'server': node.server,
        'port': node.port,
        'encryption': node.protocol.encryption
    }
    
    if node.protocol.special_param:
        result['special-param'] = node.protocol.special_param
    
    if node.tls and node.tls.enabled:
        result['tls'] = True
        result['skip-cert-verify'] = node.tls.skip_cert_verify
    
    return result
```

#### 4.2 其他平台渲染器

为支持该协议的每个平台创建对应的渲染器文件。

### 5. 更新协议导入

在各平台的 `protocols/__init__.py` 中导入新协议：

```python
# src/subio2/parsers/clash/protocols/__init__.py
from . import shadowsocks
from . import vmess
from . import trojan
from . import newprotocol  # 添加这行
```

## 添加新平台

### 1. 创建平台目录结构

```bash
mkdir -p src/subio2/parsers/newplatform/protocols
mkdir -p src/subio2/renderers/newplatform/protocols
```

### 2. 创建解析器

创建 `src/subio2/parsers/newplatform/base.py`：

```python
from typing import List, Optional, Dict, Any
from ...core.registry import parser_registry
from ...models.node_composite import CompositeNode
from ..base import BaseParser
from .protocols.registry import protocol_registry

@parser_registry.decorator('newplatform')
class NewPlatformParser(BaseParser):
    """新平台配置解析器"""
    
    def __init__(self):
        super().__init__()
        # 触发协议注册
        from . import protocols
    
    def parse(self, content: str) -> List[CompositeNode]:
        """解析新平台的配置格式"""
        nodes = []
        
        # 实现平台特定的解析逻辑
        # 例如：解析 JSON/YAML/INI 等格式
        
        return nodes
```

### 3. 创建协议注册表

创建 `src/subio2/parsers/newplatform/protocols/registry.py`：

```python
from typing import Dict, Callable, Any, Optional
from ....models.node_composite import CompositeNode

class ProtocolRegistry:
    def __init__(self):
        self._parsers: Dict[str, Callable] = {}
    
    def register(self, protocol_type: str):
        def decorator(func: Callable):
            self._parsers[protocol_type] = func
            return func
        return decorator
    
    def get_parser(self, protocol_type: str) -> Optional[Callable]:
        return self._parsers.get(protocol_type)

protocol_registry = ProtocolRegistry()
```

### 4. 创建渲染器

创建 `src/subio2/renderers/newplatform/base.py`：

```python
from typing import List, Dict, Any, Optional
from ...core.registry import renderer_registry
from ...models.node_composite import CompositeNode
from ..base import BaseRenderer

@renderer_registry.decorator('newplatform')
class NewPlatformRenderer(BaseRenderer):
    """新平台配置渲染器"""
    
    def __init__(self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None):
        super().__init__(template_dir, snippet_dir)
        # 触发协议注册
        from . import protocols
    
    def render(self, nodes: List[CompositeNode], template: Optional[str] = None, context: Dict[str, Any] = None) -> str:
        """渲染为新平台的配置格式"""
        if template and self.template_dir:
            # 使用模板渲染
            return self._render_template(template, nodes, context)
        else:
            # 直接渲染
            lines = []
            for node in nodes:
                line = self._render_node(node)
                if line:
                    lines.append(line)
            return '\n'.join(lines)
    
    def _render_node(self, node: CompositeNode) -> Optional[str]:
        """渲染单个节点"""
        # 实现节点渲染逻辑
        pass
```

### 5. 更新导入

在 `src/subio2/parsers/__init__.py` 中导入新解析器：

```python
from .clash import ClashParser
from .v2rayn import V2rayNParser
from .surge import SurgeParser
from .newplatform import NewPlatformParser  # 添加这行
```

在 `src/subio2/renderers/__init__.py` 中导入新渲染器：

```python
from .clash import ClashRenderer
from .v2rayn import V2rayNRenderer
from .surge import SurgeRenderer
from .newplatform import NewPlatformRenderer  # 添加这行
```

## 处理平台差异

### 继承和覆盖模式

对于类似 Stash（Clash 的 fork）这样的平台，可以通过继承来复用代码：

```python
# src/subio2/renderers/stash/base.py
from ..clash.base import ClashRenderer
from ...core.registry import renderer_registry

@renderer_registry.decorator('stash')
class StashRenderer(ClashRenderer):
    """Stash 渲染器 - 继承 Clash 并覆盖特定协议"""
    
    def __init__(self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None):
        super().__init__(template_dir, snippet_dir)
        # 覆盖或添加 Stash 特定的协议
        from . import protocols  # 导入 Stash 特定协议
    
    def render_node(self, node: CompositeNode) -> Dict[str, Any]:
        """覆盖节点渲染以处理 Stash 特定格式"""
        result = super().render_node(node)
        
        # Stash 特定的修改
        if node.protocol.get_type() == NodeType.HYSTERIA:
            # Stash 对 Hysteria 有不同的字段名
            result['auth-str'] = result.pop('auth_str', None)
        
        return result
```

## 测试指南

### 1. 单元测试

为新协议/平台创建测试：

```python
# tests/test_newprotocol.py
import pytest
from src.subio2.parsers.clash import ClashParser
from src.subio2.models.node_composite import NewProtocolConfig

def test_newprotocol_parsing():
    parser = ClashParser()
    content = """
proxies:
  - name: test-new
    type: newprotocol
    server: example.com
    port: 443
    encryption: aes-256
    """
    nodes = parser.parse(content)
    assert len(nodes) == 1
    assert isinstance(nodes[0].protocol, NewProtocolConfig)
    assert nodes[0].protocol.encryption == 'aes-256'

def test_newprotocol_rendering():
    from src.subio2.renderers.clash import ClashRenderer
    from src.subio2.models.node_composite import CompositeNode, NewProtocolConfig
    
    node = CompositeNode(
        name='test',
        server='example.com',
        port=443,
        protocol=NewProtocolConfig(encryption='aes-256')
    )
    
    renderer = ClashRenderer()
    result = renderer.render_node(node)
    assert result['type'] == 'newprotocol'
    assert result['encryption'] == 'aes-256'
```

### 2. 集成测试

在 `example/config.toml` 中添加测试配置：

```toml
[[artifacts]]
name = "test-newplatform.conf"
template = "newplatform.conf"
provider = "test-provider"
renderer = "newplatform"
```

### 3. 端到端测试

```bash
# 测试新平台输出
cd example
uv run subio2

# 检查输出文件
cat dist-subio2/test-newplatform.conf
```

## 最佳实践

1. **模块化设计**：每个协议在独立文件中实现，便于维护和测试
2. **自动注册**：使用装饰器模式自动注册协议解析器/渲染器
3. **保持协议独立性**：每个协议配置类应该只包含该协议特有的字段
4. **使用组合而非继承**：通过组合 `BasicAuth`、`TLSConfig` 等组件复用通用功能
5. **验证输入数据**：在 `validate()` 方法中实现数据验证
6. **处理边缘情况**：考虑缺失字段、无效数据等情况
7. **遵循平台约定**：了解目标平台的配置格式和命名约定
8. **编写文档**：为新协议/平台添加使用示例和配置说明

## 常见协议字段映射

不同平台对相同字段可能有不同的命名，以下是常见映射：

| 通用字段 | Clash | Surge | V2rayN | DAE |
|---------|-------|-------|---------|-----|
| 服务器地址 | server | server | address | server |
| 端口 | port | port | port | port |
| 密码 | password | password | password | password |
| 加密方式 | cipher | encrypt-method | method | method |
| TLS | tls | tls | tls | tls |
| 跳过证书验证 | skip-cert-verify | skip-cert-verify | allowInsecure | skip-cert-verify |

## 调试技巧

1. **启用调试日志**：
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **打印中间结果**：
   ```python
   print(f"Parsed node: {node}")
   print(f"Protocol type: {node.protocol.get_type()}")
   ```

3. **使用断点调试**：
   ```python
   import pdb; pdb.set_trace()
   ```

4. **验证注册状态**：
   ```python
   from src.subio2.core.registry import parser_registry, renderer_registry
   print(f"Registered parsers: {list(parser_registry._items.keys())}")
   print(f"Registered renderers: {list(renderer_registry._items.keys())}")
   ```

## 贡献指南

1. Fork 项目并创建功能分支
2. 遵循现有代码风格
3. 为新功能添加测试
4. 更新文档
5. 提交 Pull Request

欢迎贡献新的协议和平台支持！