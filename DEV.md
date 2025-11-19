# 开发文档 (SubIO V2)

本文档旨在帮助贡献者理解 SubIO V2 的架构，并指导如何添加对新代理协议或新平台配置格式的支持。

## 1. 核心架构

SubIO V2 采用了 Pipeline 架构，数据流向清晰：

`Config` -> `Providers (Input)` -> `Parser` -> **`Internal Models (Nodes)`** -> `Processor (Filter/Rename)` -> `Emitter` -> `Artifacts (Output)` -> `Uploader`

所有转换的核心都在于**内部数据模型 (Internal Models)**。任何外部格式都必须先解析为内部模型，然后再从内部模型生成目标格式。

### 1.1 目录结构

*   `src/subio_v2/model/`: 定义核心数据结构（节点类型、配置项）。
*   `src/subio_v2/parser/`: 负责将外部格式（Clash, Surge, V2RayN 等）解析为内部模型。
*   `src/subio_v2/emitter/`: 负责将内部模型转换为外部格式。
*   `src/subio_v2/workflow/`: 串联整个执行流程。

## 2. 如何添加新协议 (New Protocol)

假设你要添加对 `Hysteria2` 协议的支持。

### 步骤 1: 定义数据模型
修改 `src/subio_v2/model/nodes.py`：

1.  在 `Protocol` 枚举中添加新类型：
    ```python
    class Protocol(StrEnum):
        # ...
        HYSTERIA2 = "hysteria2"
    ```
2.  定义 `Hysteria2Node` 数据类，继承自 `BaseNode`：
    ```python
    @dataclass
    class Hysteria2Node(BaseNode):
        password: str = ""
        obfs: Optional[str] = None
        obfs_password: Optional[str] = None
        tls: TLSSettings = field(default_factory=TLSSettings)
        
        def __post_init__(self):
            if self.type != Protocol.HYSTERIA2:
                self.type = Protocol.HYSTERIA2
    ```
3.  将新节点类型添加到 `Node` 联合类型中：
    ```python
    Node = Union[..., Hysteria2Node]
    ```

### 步骤 2: 更新解析器 (Parser)
修改相关的 Parser（如 `ClashParser`, `V2RayNParser`），添加对新协议的解析逻辑。

例如在 `src/subio_v2/parser/clash.py`：
```python
    def _parse_node(self, data: Dict[str, Any]) -> Node | None:
        # ...
        if node_type == "hysteria2":
            return self._parse_hysteria2(data)
    
    def _parse_hysteria2(self, data: Dict[str, Any]) -> Hysteria2Node:
        return Hysteria2Node(
            type=Protocol.HYSTERIA2,
            password=data.get("password", ""),
            # ... 其他字段映射
            **self._base_fields(data)
        )
```

### 步骤 3: 更新生成器 (Emitter)
修改相关的 Emitter（如 `ClashEmitter`, `SurgeEmitter`），添加对新协议的生成逻辑。

例如在 `src/subio_v2/emitter/clash.py`：
```python
    def _emit_node(self, node: Node) -> Dict[str, Any] | None:
        # ...
        elif isinstance(node, Hysteria2Node):
            base.update({
                "password": node.password,
                "obfs": node.obfs,
                # ...
            })
            self._add_tls(base, node.tls)
```

## 3. 如何添加新平台 (New Platform)

假设你要添加对 `Sing-box` 平台的支持。

### 步骤 1: 实现解析器 (Parser) (可选)
如果需要将 Sing-box 配置文件作为输入源（Provider），请在 `src/subio_v2/parser/` 下新建 `singbox.py`：

```python
from src.subio_v2.parser.base import BaseParser
from src.subio_v2.model.nodes import Node
# ...

class SingBoxParser(BaseParser):
    def parse(self, content: Any) -> List[Node]:
        # 实现解析逻辑，返回 Node 列表
        pass
```

### 步骤 2: 实现生成器 (Emitter)
如果需要生成 Sing-box 配置文件（Artifact），请在 `src/subio_v2/emitter/` 下新建 `singbox.py`：

```python
from src.subio_v2.emitter.base import BaseEmitter
from src.subio_v2.model.nodes import Node
# ...

class SingBoxEmitter(BaseEmitter):
    def emit(self, nodes: List[Node]) -> Any:
        # 实现生成逻辑，返回 dict (JSON结构) 或 str (文本)
        pass
```

### 步骤 3: 注册到 Workflow
修改 `src/subio_v2/workflow/engine.py`：

1.  引入新的 Parser/Emitter。
2.  在 `__init__` 中实例化：
    ```python
    self.singbox_parser = SingBoxParser()
    self.singbox_emitter = SingBoxEmitter()
    ```
3.  在 `_load_providers` 中添加类型判断：
    ```python
    elif p_type == "sing-box":
        nodes = self.singbox_parser.parse(content)
    ```
4.  在 `_generate_artifacts` 中添加类型判断：
    ```python
    elif a_type == "sing-box":
        output = self.singbox_emitter.emit(nodes)
        self._write_text_artifact(name, output, ...) # 或 _write_json_artifact
    ```

## 4. 调试与测试

*   使用 `export DEBUG=1` 环境变量可启用部分调试日志。
*   可以直接运行 `python3 -m src.subio_v2.main example/config.toml` 来测试修改效果。
*   生成的配置文件位于 `dist/` 目录下，请仔细检查输出是否符合预期。
