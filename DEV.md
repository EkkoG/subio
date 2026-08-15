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

- **Parser**：`src/subio_v2/parser/factory.py` — `clash` / `clash-meta` 共用 `ClashParser` 类型，但每次请求都会创建新实例。
- **Emitter**：`src/subio_v2/emitter/factory.py` — `clash` / `clash-meta` / `stash` 分别创建 `ClashEmitter(platform="clash")`、`ClashEmitter(platform="clash-meta")`、`ClashEmitter(platform="stash")`，使用各自能力表。

### 1.3 结构化转换结果

v2 保留原有 `parse()` / `emit()` 兼容 API，同时提供用于 workflow 的结构化接口：

- `ParseResult(nodes, issues, resources)`：返回成功解析的节点、单项解析问题和文档级资源；Surge keystore 通过 `resources["keystore"]` 传递，不再依赖 parser 实例旁路。
- `EmissionResult(content, supported_nodes, issues, extras, emitted_policy_names, emitted_resource_keys)`：返回实际输出、真正可生成的节点、转换问题、模板附加上下文，以及不依赖普通 Node 的文档策略/资源清单。
- `WorkflowResult(generated, uploaded, issues)`：汇总本次运行的产物、上传结果和全部问题。

`ConversionIssue` 包含 `severity`、`stage`、`code`、`source`、`artifact`、`user`、`node`、`protocol`、`target`、`field` 等上下文。默认只要存在 ERROR，artifact 就不会写入或上传；确需生成有损示例时，可在全局或单个 artifact 显式设置：

```toml
allow_conversion_errors = true
```

该选项会放行全部转换错误，应只用于已审阅的配置，不应作为普通默认值。

### 1.4 Surge 语法层

Surge 代理行不能使用普通 `str.split(",")` 解析。参数值可以用双引号包含逗号，值内也
可以包含等号；部分文档对象还允许重复参数。共享实现位于
`src/subio_v2/surge/syntax.py`：

- `parse_proxy_line()` 将一行代理解析为 `SurgeProxyRecord`；
- `SurgeParameters` 按输入顺序保留参数和重复 key，`.get()` 返回最后一个值；
- `serialize_proxy_line()` 根据逗号、引号和首尾空白自动引用参数值；
- `parse_parameter_list()` / `serialize_parameter_list()` 用于 Keystore 等纯 key/value 列表。
- `split_comma_separated()` 额外识别括号嵌套，用于 WireGuard 的多个 `peer=(...)` 记录。

Surge Parser 应先经过语法层，再把已知字段映射到 Node；Emitter 应先构造 record，再由
语法层生成文本。新增字段时不得恢复手写逗号拼接，也不得使用普通字典承载需要保序或
允许重复的原始参数。

UDP 参数必须按协议生成：只有 SOCKS5、Shadowsocks，以及未来的 External 和
HTTP/2 CONNECT 使用显式 `udp-relay`。VMess、Trojan、TUIC、Hysteria 2 和 Snell v3+
的 UDP 支持是协议能力，不应因为 `node.udp=True` 输出该参数；HTTP/HTTPS 和 SSH 不支持
UDP relay。

Surge 已知但不跨平台的公共参数存入 `BaseNode.surge_options`，未知参数按顺序存入
`BaseNode.source_extensions["surge"]`。Surge 输出会写回这些字段；其他目标输出必须返回
`conversion.unconsumed-source-field` issue，不能静默丢弃。

过渡期内，尚未迁移的 Keystore、未引用命名 section 和真正的 Surge-only policy 仍由
`src/subio_v2/surge/resources.py` 中的 `SurgeDocumentResources` 承载。资源合并按类型和名称
检测冲突，敏感内容不得进入 dataclass repr、日志或 issue message；不要再向这条文档旁路
新增可跨平台协议。

WireGuard 的 policy line 映射为强类型 `WireguardNode`，多个 peer 会映射到
`WireguardNode.peers`。Tailscale 映射为无伪造端点的 `TailscaleNode`，引用的
`[Tailscale <name>]` section 绑定到该节点的 `SurgeNodeAttachments`；改名、过滤、用户覆盖和
capability 检查都作用于节点。`direct` / `reject*` alias 仍是待迁移的文档策略，因此
workflow 判断过渡期 Surge artifact 是否为空时仍需兼顾 `EmissionResult.emitted_policy_names`。

MASQUE 和 Trust Tunnel 均使用强类型节点。`MasqueNode.mode` 区分 Surge 的标准
HTTP/3 CONNECT/CONNECT-UDP forward proxy、Mihomo CONNECT-IP 和 Mihomo
`h3-l4proxy`；传输与 method/profile 分开表示。当前两端没有重叠的 MASQUE 部署/认证
profile，跨端生成必须返回 `conversion.unsupported-protocol-variant`，不能伪造设备密钥、
隧道地址或把 HTTP Basic 凭据推导成 WARP 凭据。Trust Tunnel 的 H2/H3、TLS 和
`max-streams` 可跨平台映射；UDP、WebSocket、headers 和平台扩展按 capability 明确报告。

External Proxy Program 使用独立的 `SurgeExternalPolicy`，不能进入普通 opaque 列表。默认
拒绝所有来源；仅本地 `file` provider 显式设置 `allow_unsafe_external = true` 时允许，并且
仍只能输出到 Surge。URL provider 禁止启用该开关，远程内容即使经过 age 解密仍按远程来源
处理。被拒绝的 External record 必须在 parser 阶段从资源中移除，所以
`allow_conversion_errors = true` 不能恢复它；issue 和日志不得包含 `exec`、`args` 或
`addresses` 的值。

Surge `h2-connect` 使用 `HttpNode.variant=HttpVariant.H2_CONNECT`，不得退化为普通
HTTP/HTTPS；AnyTLS 的 `reuse=false` 也是有语义的来源字段。非 Surge 目标无法表达这些
字段时必须由 descriptor 返回 capability error。

### 1.5 Surge Codec 注册表

`src/subio_v2/surge/codecs.py` 是 Surge policy keyword 的单一规格来源。每个
`SurgeCodecSpec` 同时声明：

- Surge keyword 与对应 `Protocol`；
- 普通 Node、文档策略或 External 安全策略类型；
- emitter handler；
- 已消费参数、规范化参数和多值参数；
- `EXPLICIT`、`AUTOMATIC`、`VERSIONED` 或 `UNSUPPORTED` UDP 行为。

Surge capability 的协议集合、Emitter `_HANDLERS`、Parser consumed parameter 表和 UDP
参数校验都从该注册表派生。新增或修改 Surge 协议时，应先更新 codec spec，再实现 parser /
emitter 逻辑；`tests/test_subio_v2_surge_codec_invariants.py` 会检查 capability、handler、
parser keyword、参数生成路径和 UDP 矩阵是否漂移。不要在 parser、emitter 或 capability 中
另建一份 keyword 列表。

当前目标版本常量为 `DEFAULT_SURGE_TARGET = "latest"`。Parser/Emitter 已保留
`target_version` 构造参数，但在实现明确的版本字段裁剪前只接受 `latest`，不得通过传入旧
版本字符串假装完成兼容。

更新官方 fixture 时：

1. 用 MarkItDown 或等价的只读网页提取工具读取官方页面；
2. 在 `tests/fixtures/surge/official/` 保存最小、无真实凭据的离线示例；
3. 在该目录 `README.md` 记录来源 URL 和复核日期；
4. 更新 codec spec、字段/UDP 不变量和对应 round-trip/security 测试；
5. 测试运行时不得访问网络。

## 2. Clash / Mihomo 协议支持（Protocol Registry）

`ClashParser` / `ClashEmitter` 对齐 [meta-json-schema](https://github.com/dongchengjie/meta-json-schema) 中 `proxies` 的 **22 种已知** `type`，并能把未来未知 `type` 作为 Mihomo-only 透传节点保留。

### 2.1 实现方式一览

| Clash `type` | 内部模型 | 跨平台 |
|--------------|----------|--------|
| `ss`, `vmess`, `vless`, `trojan`, `socks5`, `http` | 强类型 `*Node` | 可扩展 Surge / dae 等 |
| `ssr`, `hysteria`, `tuic`, `snell`, `wireguard`, `hysteria2`, `anytls`, `ssh` | 强类型 + `BaseNode.extra` | 部分已有 / 可继续补 |
| `masque`, `trusttunnel`, `tailscale` | 强类型 + `BaseNode.extra` | Mihomo/Surge 按协议变体与字段能力转换 |
| `mieru`, `sudoku`, `openvpn`, `direct`, `dns` | `ClashPassthroughNode` | **仅 Clash 往返** |
| 未来未知 `type` | `ClashPassthroughNode(clash_type=...)` | **仅 Mihomo 往返** |

### 2.2 实现结构

当前 Clash 路径是**描述符注册**模型：

- `parser/clash.py` 只做 YAML 解析 + `protocols.by_clash_type(type)` 分发；
- `emitter/clash.py` 只做遍历 + `protocols.get(node.type)` 分发；
- 14 个强类型协议继承 `StructuredProtocolDescriptor`，通过同一组 `ClashFieldSpec` 派生 consumed keys、模型属性、required 校验、parse 和 emit；
- 特殊协议逻辑可覆写 `prepare_parse_kwargs()`、`after_parse()`、`after_emit()` 和 `check()`；
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

强类型协议不再手写 `handled`。`ClashFieldSpec.consumed_keys` 必须只包含已写入模型、
且能由同一规格重新生成的字段。尚未跨平台建模、但需要 Clash 往返保留的字段应交给
`extra` / `merge_extra` 透传。`EmitPolicy.ALWAYS`、`TRUTHY`、`NOT_NONE` 用于明确控制
空字符串、`false`、`0` 和 `None` 的输出语义；关键凭据可设置 `required=True`。

传输层同样遵循该规则：`TransportSettings.network` 可保留尚未纳入 `Network` 枚举的
新传输名称，`TransportSettings.extra` 按 `ws-opts` / `grpc-opts` 等嵌套配置块保存未
建模子字段。解析器只从当前 active transport block 提取强类型字段；非 active 的
`ws-opts` / `http-opts` / `h2-opts` / `grpc-opts` 必须完整保留。未知 network 不得降级
为 `tcp`，也不得因读取了部分子字段而丢弃整个 opts 配置块的其余内容。

### 2.4 `ClashPassthroughNode`（透传节点）

用于 **Clash Meta 独有、暂不跨平台** 的协议。解析时把整段 proxy 字典存入 `raw`；生成时 `emit_passthrough()` 深拷贝 `raw` 并覆盖 `name` / `server` / `port` 等 `BaseNode` 字段（便于过滤、改名）。

```text
Clash YAML → ClashPassthroughNode(raw=完整 dict) → ClashEmitter → Clash YAML
```

透传协议列表在 `src/subio_v2/protocols/passthrough.py` 中注册。

对于注册表中不存在的未来 Clash/Mihomo `type`，parser 会使用动态透传 descriptor 保存
完整 raw 字典和原始 `clash_type`。该节点只能由 `clash-meta` emitter 输出；原版 Clash、
Stash 和其他平台会通过 capability 检查明确拒绝。

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

1. 校验非透传节点的 `name`、`server`、`port` 和 descriptor 声明的 required 字段；
2. 检查平台是否支持该协议；
3. 读取 `proto_caps` 并调用 `protocols.get(node.type).check(...)`；
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

1. 定义 `XxxDescriptor(StructuredProtocolDescriptor)`，声明 `protocol` / `clash_type` / `node_class`；
2. 用 `scalar_field()`、`tls_group()`、`transport_group()`、`smux_group()` 或 `field_group()` 声明 `fields`；
3. 对关键凭据设置 `required=True`，并选择正确的 `EmitPolicy`；
4. 如有特殊逻辑，覆写 descriptor hook 或 `check()`，不要重新维护另一套 consumed keys；
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
class ExampleDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.EXAMPLE
    clash_type = "example"
    node_class = ExampleNode
    fields = (
        scalar_field(
            "password",
            default="",
            emit_policy=EmitPolicy.ALWAYS,
            required=True,
        ),
        tls_group(),
        smux_group(),
    )

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

Tailscale 这类没有远端 `server/port` 的协议应将 descriptor 的 `requires_endpoint` 设为
`False`，并在 Clash emitter 中删除空端点字段；不得用占位地址绕过通用校验。协议同名但
method/profile 不同（如 MASQUE）时，应在节点模型和 capability 中显式分型。

## 6. 如何添加新平台

假设添加 `sing-box` 输出格式。

### 步骤 1：Parser（可选）

在 `src/subio_v2/parser/` 新建解析器，继承 `BaseParser`，实现 `parse_result()` 并在
`parser/factory.py` 注册。单项失败应返回 `ConversionIssue`；顶层不可解析输入应抛
`ValueError`。文档级 sidecar 数据通过 `ParseResult.resources` 返回。

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
uv run subio convert example/config.toml --dry-run
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
