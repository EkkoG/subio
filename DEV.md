# 开发文档 (SubIO V2)

本文档帮助贡献者理解 SubIO V2 的架构，并说明如何扩展代理协议与平台格式。

## 1. 核心架构

SubIO V2 采用 Pipeline 架构：

`Config` → `Providers (Input)` → `Parser` → **Internal Models (Nodes)** → `Processor (Filter/Rename)` → `Emitter` → `Artifacts (Output)` → `Uploader`

所有转换都经过**内部数据模型**。外部格式必须先解析为 `Node`，再生成目标格式。

### 1.1 目录结构

| 路径 | 职责 |
|------|------|
| `src/subio_v2/model/` | 节点类型、`Protocol` 枚举、`TLSSettings` / `TransportSettings` 等 |
| `src/subio_v2/parser/` | 将 Clash、Surge、V2RayN 等解析为 `Node` |
| `src/subio_v2/emitter/` | 将 `Node` 生成为目标格式 |
| `src/subio_v2/protocols/` | 协议注册中心与每协议 Clash parse/emit/check 描述符 |
| `src/subio_v2/clash/` | Clash/Mihomo 共享的 parse/emit 辅助函数 |
| `src/subio_v2/capabilities/` | 各平台协议能力定义与生成前检查 |
| `src/subio_v2/workflow/` | 配置加载、模板渲染、上传 |
| `vendor/meta-json-schema/` | [meta-json-schema](https://github.com/dongchengjie/meta-json-schema)（Clash Meta 字段参考，可选） |

### 1.2 工厂注册

- **Parser**：`src/subio_v2/parser/factory.py` — `clash` / `clash-meta` 共用 `ClashParser`
- **Emitter**：`src/subio_v2/emitter/factory.py` — `clash` / `clash-meta` / `stash` 共用 `ClashEmitter(platform="clash-meta")`

## 2. Clash / Mihomo 协议支持（Protocol Registry）

`ClashParser` / `ClashEmitter` 对齐 [meta-json-schema](https://github.com/dongchengjie/meta-json-schema) 中 `proxies` 的 **22 种** `type`。

### 2.1 实现方式一览

| Clash `type` | 内部模型 | 跨平台 |
|--------------|----------|--------|
| `ss`, `vmess`, `vless`, `trojan`, `socks5`, `http` | 强类型 `*Node` | 可扩展 Surge / dae 等 |
| `ssr`, `hysteria`, `tuic`, `snell`, `wireguard`, `hysteria2`, `anytls`, `ssh` | 强类型 + `BaseNode.extra` | 部分已有 / 可继续补 |
| `mieru`, `sudoku`, `masque`, `trusttunnel`, `openvpn`, `tailscale`, `direct`, `dns` | `ClashPassthroughNode` | **仅 Clash 往返** |

### 2.2 实现结构

当前 Clash 路径是**描述符注册**模型：

- `parser/clash.py` 只做 YAML 解析 + `protocols.by_clash_type(type)` 分发；
- `emitter/clash.py` 只做遍历 + `protocols.get(node.type)` 分发；
- 每个协议在 `src/subio_v2/protocols/*.py` 中自包含：
  - `parse_clash(data) -> Node`
  - `emit_clash(node) -> dict`
  - `check(node, proto_caps, platform) -> list[CapabilityWarning]`
- `protocols/passthrough.py` 统一注册 Clash-only 透传协议描述符。

换句话说，`ClashParser` / `ClashEmitter` 不再维护 `_parse_xxx` / `_emit_xxx` 巨型分支。

### 2.3 强类型节点与 `extra`

常见协议使用独立 dataclass（如 `VmessNode`）。解析时：

1. 映射常用字段到 dataclass 属性；
2. 未映射字段写入 `BaseNode.extra`；
3. 生成时用 `merge_extra()` 写回，保证 Clash 配置往返不丢字段。

共享逻辑在 `src/subio_v2/clash/helpers.py`：

- `parse_base_fields` / `emit_base` — 名称、服务器、`tfo`、`dialer-proxy` 等
- `parse_tls` / `emit_tls`、`parse_transport` / `emit_transport`、`parse_smux` / `emit_smux`
- `assign_extra` / `merge_extra`

### 2.4 `ClashPassthroughNode`（透传节点）

用于 **Clash Meta 独有、暂不跨平台** 的协议。解析时把整段 proxy 字典存入 `raw`；生成时 `emit_passthrough()` 深拷贝 `raw` 并覆盖 `name` / `server` / `port` 等 `BaseNode` 字段（便于过滤、改名）。

```text
Clash YAML → ClashPassthroughNode(raw=完整 dict) → ClashEmitter → Clash YAML
```

透传协议列表在 `src/subio_v2/protocols/passthrough.py` 中注册。

**适用**：订阅里要原样保留、且不需要转 Surge/dae 的节点。  
**不适用**：需要在多平台间转换的协议（应改为强类型，见第 5 节）。

### 2.5 查阅字段定义

1. **推荐**：`vendor/meta-json-schema/src/modules/adapter/outbound/<协议>.json`
2. 打包后的完整 schema：`vendor/meta-json-schema/schemas/meta-json-schema.json`
3. 代理类型入口：`vendor/meta-json-schema/src/modules/config/proxies.json`

本地未克隆时可执行：

```bash
git clone --depth 1 https://github.com/dongchengjie/meta-json-schema.git vendor/meta-json-schema
```

## 3. 平台能力（Capabilities）

`src/subio_v2/capabilities/definitions.py` 声明各平台支持的协议、加密方式、传输类型等。  
`CapabilityChecker`（`checker.py`）在 `BaseEmitter.emit_with_check()` 中过滤不支持的节点并打日志。

当前 `CapabilityChecker` 的协议级检查路径为：

1. 检查平台是否支持该协议；
2. 读取 `proto_caps`；
3. 调用 `protocols.get(node.type).check(...)`；
4. 再做 `tfo` / `mptcp` / `dialer_proxy` 全局特性检查。

即：字段级协议检查逻辑已下沉到 `protocols/*.py`，不再在 `checker.py` 中维护 `_check_xxx` 分支。

添加 Clash 新协议时，请同步更新 `clash-meta`（及需要兼容的 `clash` / `stash`）下的 `protocols` 与协议子配置。

## 4. 如何添加新协议（当前推荐流程）

以在 Clash 侧新增/完善某协议为例（跨平台按需补 Surge/Link）。

### 步骤 1：定义数据模型

修改 `src/subio_v2/model/nodes.py`：

1. 在 `Protocol` 枚举中增加项；
2. 新增 dataclass（继承 `BaseNode`），必要时使用 `TLSSettings` / `SmuxSettings`；
3. 将类型加入 `Node` 联合类型。

### 步骤 2：新增协议描述符

在 `src/subio_v2/protocols/` 新建 `xxx.py`：

1. 定义 `XxxDescriptor(ProtocolDescriptor)`，声明 `protocol` / `clash_type` / `node_class`；
2. 实现 `parse_clash()`（可复用 `clash/helpers.py` 中的 `parse_*` / `assign_extra`）；
3. 实现 `emit_clash()`（`emit_base` + 协议字段 + `emit_*` + `merge_extra`）；
4. （推荐）实现 `check()`，写该协议平台能力检查；
5. 末尾调用 `register(XxxDescriptor())`。

然后在 `protocols/__init__.py` 的 `_bootstrap()` 里导入该模块，完成注册。

若协议属于透传类，使用 `protocols/passthrough.py` 的 `PassthroughDescriptor` 注册。

### 步骤 3：其他平台（可选）

按需修改：

- `emitter/surge.py`：新增 `_parts_xxx()`，并加入 `_HANDLERS[Protocol.XXX]`；
- `emitter/link.py`：新增 `build_xxx_url()`，并加入 `builders[Protocol.XXX]`（供 `v2rayn` / `dae` 复用）。

### 步骤 4：能力与测试

1. 更新 `capabilities/definitions.py`；
2. 在对应 `protocols/xxx.py` 的 `check()` 中增加字段级检查（如有需要）；
3. 在 `tests/test_subio_v2_parser_clash*.py` 增加用例；全量协议可参考 `tests/test_subio_v2_parser_clash_all_protocols.py`。

### 示例：协议描述符（强类型 + extra）

```python
class ExampleDescriptor(ProtocolDescriptor):
    protocol = Protocol.EXAMPLE
    clash_type = "example"
    node_class = ExampleNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
    handled = {"password", "tls", "sni", "smux", ...}
    node = ExampleNode(
        type=Protocol.EXAMPLE,
        password=data.get("password", ""),
        tls=parse_tls(data),
        smux=parse_smux(data),
        **parse_base_fields(data),
    )
    assign_extra(node, data, handled)
    return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        base = emit_base(node)
        base["password"] = node.password
        emit_tls(base, node.tls)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

register(ExampleDescriptor())
```

## 5. 将透传协议改为跨平台

若某协议需从 `ClashPassthroughNode` 迁出：

1. 按 schema 新增 `XxxNode` dataclass；
2. 新建 `protocols/xxx.py` 描述符实现 `parse_clash` / `emit_clash`，并从 `protocols/passthrough.py` 的注册列表移除；
3. 实现目标平台 Parser/Emitter；
4. 更新各平台 `PLATFORM_CAPABILITIES`；
5. 补充 Clash 往返 + 跨平台 golden 测试。

迁移时可从 `ClashPassthroughNode.raw` 写一次性转换函数，无需用户重导订阅。建议优先 **强类型 + `extra`**（与 `TUICNode` 相同），不必维护两套逻辑。

## 6. 如何添加新平台

假设添加 `sing-box` 输出格式。

### 步骤 1：Parser（可选）

在 `src/subio_v2/parser/` 新建解析器，继承 `BaseParser`，在 `parser/factory.py` 注册。

### 步骤 2：Emitter

在 `src/subio_v2/emitter/` 新建生成器，继承 `BaseEmitter`（设置 `platform` 以启用能力检查），在 `emitter/factory.py` 注册。  
推荐在该 emitter 内使用 `Protocol -> handler` 的 dict 分发（与 `surge.py` / `link.py` 一致）。

### 步骤 3：Workflow

在 `workflow/engine.py` 的 provider / artifact 分支中接入新类型；模板渲染见 `workflow/template.py`。

### 步骤 4：能力表

在 `capabilities/definitions.py` 增加 `"sing-box": { "protocols": {...}, ... }`。

## 7. 调试与测试

### 运行示例

```bash
uv run subio example/config.toml --dry-run
```

输出目录：`./dist/`（见 `AGENTS.md`）。

### 单元测试

```bash
# 全量
uv run python -m pytest tests/

# Clash 相关
uv run python -m pytest tests/test_subio_v2_parser_clash*.py -v
```

建议：先跑 `example/`，再改/增 `tests/` 用例。

### 调试日志

部分模块支持 `DEBUG=1` 环境变量。

### VS Code 校验 Clash 模板（可选）

在 `.vscode/settings.json` 中关联 schema：

```json
{
  "yaml.schemas": {
    "./vendor/meta-json-schema/schemas/meta-json-schema.json": "example/**/*.yaml"
  }
}
```

## 8. 相关文档

- `README.md` — 用户使用说明
- `AGENTS.md` — 仓库内 Agent 运行约定
- `tests/README.md` — 测试目录说明
- `v2_plan.md` — V2 规划（历史参考）
