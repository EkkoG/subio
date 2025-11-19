# SubIO v2 重构计划

## 1. 目标与原则

*   **独立性**：所有代码将在 `src/subio_v2` 下全新实现，不依赖现有代码，便于并行开发与对比。
*   **结构优先**：采用清晰的分层架构，核心是解耦“数据模型”与“转换逻辑”。
*   **易测试**：核心逻辑（解析、转换、生成）必须是纯函数或无副作用的类，易于编写单元测试。
*   **易扩展**：新协议只需定义数据模型，新平台只需实现 Parser/Emitter 接口。
*   **兼容性**：保持 `example/config.toml` 配置文件格式不变，输出结果在功能上与 v1 保持一致。

## 2. 架构设计

采用 **Pipeline** 架构，数据流向如下：

`Config` -> `Providers (Load & Parse)` -> `Internal Models (Nodes)` -> `Processors (Filter, Rename, etc.)` -> `Artifacts (Emit & Template)` -> `Uploaders`

### 2.1 核心模块划分 (`src/subio_v2`)

*   **`model`**: 定义核心数据结构。使用 `dataclasses` 或 `pydantic`（推荐，利于验证和序列化）。
    *   定义统一的中间表示（IR），覆盖所有支持协议的超集。
*   **`parser`**: 负责将外部格式（Clash, V2RayN, Surge 等）转换为内部 IR。
*   **`emitter`**: 负责将内部 IR 转换为外部格式（Clash, Surge, Dae, V2RayN 等）。
*   **`processor`**: 对节点列表进行操作的中间件，如过滤（Filter）、重命名（Rename）、去重等。
*   **`workflow`**: 串联整个执行流程，读取配置并调度各个模块。

## 3. 详细设计

### 3.1 数据模型 (Model) - The "IR"

不再使用复杂的继承与 Mixin，改用组合与 Discriminated Unions。

```python
# 伪代码示例
from enum import StrEnum
from pydantic import BaseModel, Field
from typing import Literal, Union, Optional, List

class Protocol(StrEnum):
    SHADOWSOCKS = "shadowsocks"
    VMESS = "vmess"
    # ...

class BaseNode(BaseModel):
    name: str
    type: Protocol
    server: str
    port: int
    # ...

class ShadowsocksNode(BaseNode):
    type: Literal[Protocol.SHADOWSOCKS]
    cipher: str
    password: str
    plugin: Optional[str] = None
    plugin_opts: Optional[dict] = None

# ... 其他协议定义

Node = Union[ShadowsocksNode, VmessNode, ...] # 用于类型提示
```

### 3.2 接口定义

*   **Parser Interface**:
    ```python
    class BaseParser(ABC):
        @abstractmethod
        def parse(self, content: str) -> List[Node]: ...
    ```

*   **Emitter Interface**:
    ```python
    class BaseEmitter(ABC):
        @abstractmethod
        def emit(self, nodes: List[Node]) -> Any: ... 
        # Any 可以是 dict (JSON/YAML结构) 或 str (文本配置)
    ```

### 3.3 配置文件兼容

创建一个适配层来读取 `config.toml`，将其映射到 v2 的配置对象上，确保向后兼容。

## 4. 开发步骤

1.  **基础建设**:
    *   建立 `src/subio_v2` 目录结构。
    *   定义 `model` (IR) 和基本协议类型。
2.  **核心逻辑**:
    *   实现 `parser` 框架及 Clash、V2RayN 解析器。
    *   实现 `emitter` 框架及 Clash、Surge、V2RayN、Dae 生成器。
    *   编写单元测试验证 Parser -> Model -> Emitter 的无损（或预期内损耗）转换。
3.  **业务流程**:
    *   实现 `processor` (Filter, Rename)。
    *   实现配置读取与 `workflow` 调度。
    *   集成模板渲染（Jinja2 或简单的文本替换）。
4.  **验证与交付**:
    *   运行 v2 版本，读取 `example/config.toml`。
    *   对比 v2 输出与 v1 输出的差异。
    *   修正差异，直至满足“输出基本一致”。

## 5. 扩展性说明

*   **添加新协议 (e.g. Hysteria2)**:
    1.  在 `model` 中添加 `Hysteria2Node`。
    2.  在相关 `parser` 中添加解析逻辑。
    3.  在相关 `emitter` 中添加生成逻辑。
*   **添加新平台 (e.g. Sing-box)**:
    1.  实现 `SingBoxParser` (如果需要作为源)。
    2.  实现 `SingBoxEmitter`。
    3.  在 Registry 中注册。

## 6. 待定事项

*   暂时忽略代理链（Chain）和隐私节点的高级逻辑，优先保证基础节点转换的正确性。
*   Uploader 模块可延后实现，初期仅输出文件到本地。

