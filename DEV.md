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
| `src/subio_v2/clash/` | Clash/Mihomo 共享的 parse/emit 辅助函数 |
| `src/subio_v2/capabilities/` | 各平台协议能力定义与生成前检查 |
| `src/subio_v2/workflow/` | 配置加载、模板渲染、上传 |
| `vendor/meta-json-schema/` | [meta-json-schema](https://github.com/dongchengjie/meta-json-schema)（Clash Meta 字段参考，可选） |

### 1.2 工厂注册

- **Parser**：`src/subio_v2/parser/factory.py` — `clash` / `clash-meta` 共用 `ClashParser`
- **Emitter**：`src/subio_v2/emitter/factory.py` — `clash` / `clash-meta` / `stash` 共用 `ClashEmitter(platform="clash-meta")`

## 2. Clash / Mihomo 协议支持

`ClashParser` / `ClashEmitter` 对齐 [meta-json-schema](https://github.com/dongchengjie/meta-json-schema) 中 `proxies` 的 **22 种** `type`。

### 2.1 实现方式一览

| Clash `type` | 内部模型 | 跨平台 |
|--------------|----------|--------|
| `ss`, `vmess`, `vless`, `trojan`, `socks5`, `http` | 强类型 `*Node` | 可扩展 Surge / dae 等 |
| `ssr`, `hysteria`, `tuic`, `snell`, `wireguard`, `hysteria2`, `anytls`, `ssh` | 强类型 + `BaseNode.extra` | 部分已有 / 可继续补 |
| `mieru`, `sudoku`, `masque`, `trusttunnel`, `openvpn`, `tailscale`, `direct`, `dns` | `ClashPassthroughNode` | **仅 Clash 往返** |

### 2.2 强类型节点与 `extra`

常见协议使用独立 dataclass（如 `VmessNode`）。解析时：

1. 映射常用字段到 dataclass 属性；
2. 未映射字段写入 `BaseNode.extra`；
3. 生成时用 `merge_extra()` 写回，保证 Clash 配置往返不丢字段。

共享逻辑在 `src/subio_v2/clash/helpers.py`：

- `parse_base_fields` / `emit_base` — 名称、服务器、`tfo`、`dialer-proxy` 等
- `parse_tls` / `emit_tls`、`parse_transport` / `emit_transport`、`parse_smux` / `emit_smux`
- `assign_extra` / `merge_extra`

### 2.3 `ClashPassthroughNode`（透传节点）

用于 **Clash Meta 独有、暂不跨平台** 的协议。解析时把整段 proxy 字典存入 `raw`；生成时 `emit_passthrough()` 深拷贝 `raw` 并覆盖 `name` / `server` / `port` 等 `BaseNode` 字段（便于过滤、改名）。

```text
Clash YAML → ClashPassthroughNode(raw=完整 dict) → ClashEmitter → Clash YAML
```

协议列表见 `src/subio_v2/clash/helpers.py` 中的 `PASSTHROUGH_PROTOCOLS`。

**适用**：订阅里要原样保留、且不需要转 Surge/dae 的节点。  
**不适用**：需要在多平台间转换的协议（应改为强类型，见第 5 节）。

### 2.4 查阅字段定义

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

添加 Clash 新协议时，请同步更新 `clash-meta`（及需要兼容的 `clash` / `stash`）下的 `protocols` 与协议子配置。

## 4. 如何添加新协议

以在 Clash 侧新增/完善某协议为例（跨平台需再补 Surge/dae 的 Parser/Emitter）。

### 步骤 1：定义数据模型

修改 `src/subio_v2/model/nodes.py`：

1. 在 `Protocol` 枚举中增加项；
2. 新增 dataclass（继承 `BaseNode`），必要时使用 `TLSSettings` / `SmuxSettings`；
3. 将类型加入 `Node` 联合类型。

### 步骤 2：Clash 解析

在 `src/subio_v2/parser/clash.py` 中：

1. 在 `CLASH_TYPE_TO_PROTOCOL`（`clash/helpers.py`）中注册 Clash `type` 字符串；
2. 实现 `_parse_xxx`，调用 `parse_base_fields`、`parse_tls` 等；
3. 用 `assign_extra(node, data, handled_keys)` 保留未建模字段。

若协议属于透传类，改为 `_parse_passthrough` 并加入 `PASSTHROUGH_PROTOCOLS`（仅 Clash）。

### 步骤 3：Clash 生成

在 `src/subio_v2/emitter/clash.py` 中实现 `_emit_xxx`：`emit_base` → 协议字段 → `emit_tls` / `emit_smux` → `merge_extra`。

`ClashPassthroughNode` 在 `_emit_node` 开头已统一走 `emit_passthrough`。

### 步骤 4：其他平台（可选）

按需修改 `parser/surge.py`、`emitter/surge.py`、`emitter/dae.py` 等。

### 步骤 5：能力与测试

1. 更新 `capabilities/definitions.py`；
2. 在 `checker.py` 中增加字段级检查（如有需要）；
3. 在 `tests/test_subio_v2_parser_clash*.py` 增加用例；全量协议可参考 `tests/test_subio_v2_parser_clash_all_protocols.py`。

### 示例：强类型 + extra

```python
# parser/clash.py
def _parse_example(self, data: Dict[str, Any]) -> ExampleNode:
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

# emitter/clash.py
def _emit_example(self, node: ExampleNode) -> Dict[str, Any]:
    base = emit_base(node)
    base["password"] = node.password
    emit_tls(base, node.tls)
    emit_smux(base, node.smux)
    return merge_extra(base, node)
```

## 5. 将透传协议改为跨平台

若某协议需从 `ClashPassthroughNode` 迁出：

1. 按 schema 新增 `XxxNode` dataclass；
2. 实现 `_parse_xxx` / `_emit_xxx`，并从 `PASSTHROUGH_PROTOCOLS` 移除；
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

### 步骤 3：Workflow

在 `workflow/engine.py` 的 provider / artifact 分支中接入新类型；模板渲染见 `workflow/template.py`。

### 步骤 4：能力表

在 `capabilities/definitions.py` 增加 `"sing-box": { "protocols": {...}, ... }`。

## 7. 调试与测试

### 运行示例

```bash
uv run subio2 example/config.toml --dry-run
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
