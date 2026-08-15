# SubIO v2 开发指南

本文档描述当前有效的架构边界和扩展方法。历史实现过程见 `docs/v2_fix_plan.md` 和
`docs/surge_support_plan.md`；后续工作以 `docs/development_plan.md` 为准。

## 1. 项目边界

SubIO v2 只转换两类内容：

1. 代理节点；
2. 规则及规则集。

SubIO 不是完整配置文件中转器。策略组、DNS、MITM、脚本、通用 section、客户端运行状态
等内容，不应为了“无损转换”进入通用 IR 或 workflow。

有些平台把一个节点拆到多个位置，例如 Surge 的 `[Proxy]`、`[Keystore]`、
`[WireGuard <name>]` 和 `[Tailscale <name>]`。Parser 可以读取重建节点所需的附属内容，但只能
把被该节点实际引用的部分绑定为节点附件。附件必须随节点一起被过滤、改名、能力检查和
丢弃，不能拥有独立生命周期。

转换遵循三条契约：

- **同方言保真**：源和目标属于同一配置方言时，未知但安全的节点字段应尽量往返保留；
- **跨平台显式**：目标不能表达的语义必须产生结构化 issue，不能静默改写成近似语义；
- **危险输入失败关闭**：远程内容不能获得模板执行、本地程序执行或凭据引用权限。

## 2. 数据流

```text
Config
  -> Provider
  -> Parser
  -> Node IR
  -> Processor (filter / rename / override / relation checks)
  -> CapabilityChecker
  -> Emitter
  -> Artifact
  -> Uploader
```

主要目录：

| 路径 | 职责 |
|---|---|
| `src/subio_v2/model/` | 跨平台节点语义和共享设置 |
| `src/subio_v2/parser/` | 将来源格式解析成节点和结构化问题 |
| `src/subio_v2/emitter/` | 将最终节点生成目标格式 |
| `src/subio_v2/protocols/` | Clash/Mihomo 协议 descriptor 注册表 |
| `src/subio_v2/clash/` | Clash-family 共享字段与嵌套 transport/smux 辅助函数 |
| `src/subio_v2/surge/` | Surge 词法、codec 规格、安全门禁和节点附件 |
| `src/subio_v2/capabilities/` | 当前 serializer 能表达的平台能力 |
| `src/subio_v2/workflow/` | provider、模板、artifact 和上传事务 |
| `vendor/meta-json-schema/` | Mihomo 字段参考；仅本地依赖，不提交 |

`ParserFactory` 和 `EmitterFactory` 每次返回新实例。Parser、Emitter、Uploader 的可变状态不得
跨 provider、artifact 或两次运行共享。

## 3. IR 与扩展字段

### 3.1 强类型语义

会被多个目标平台使用、参与校验或需要改名/过滤的字段，应进入 `BaseNode`、具体 `*Node`、
`TLSSettings`、`TransportSettings` 或 `SmuxSettings`。

字段名应描述协议语义，不应直接复用某个平台碰巧使用的名称。例如：

- 客户端 TLS 指纹和服务端证书 SHA-256 指纹是不同语义；
- MASQUE method/profile、传输和认证材料是不同维度；
- Tailscale 的 exit-node 选择策略与失败回退不是一个魔法字符串。

不能证明语义等价时，不要为了“支持转换”互相推导凭据、地址、默认值或协议变体。

### 3.2 同方言保真数据

- `BaseNode.extra` 当前用于 Clash/Mihomo descriptor 未建模字段的同方言往返；
- `TransportSettings.extra` 保存 `ws-opts`、`grpc-opts` 等嵌套块中的未建模字段；
- `ClashPassthroughNode.raw` 保存 Mihomo-only 或未来未知的完整 proxy 字典；
- `BaseNode.source_extensions[<dialect>]` 保存来源方言专属字段和节点附件。

这些数据不是通用语义。Emitter 只能消费属于自己目标方言的扩展；跨方言未消费内容必须
产生 `conversion.unconsumed-source-field`，不能直接合并进目标配置。

`ParseResult.resources`、`EmissionResult.emitted_policy_names` 和
`EmissionResult.emitted_resource_keys` 目前仅为兼容保留，不得承载新的完整文档资源设计。

### 3.3 节点附件

Surge 节点附件定义在 `src/subio_v2/surge/resources.py`。约束如下：

1. Parser 的 Keystore/section catalog 只在一次输入解析期间存在；
2. 只复制当前节点实际引用的条目；
3. 未引用内容不进入 `ParseResult`；
4. Emitter 只从成功生成的最终节点收集附件；
5. 同键同值去重，同键异值只淘汰后出现的冲突节点；
6. issue、日志和 `repr` 不得包含私钥、密码、auth-key 或完整 section；
7. 通用 workflow 不得导入或合并 Surge 附件。

其他平台若出现同类需求，应复用“节点所有权”原则，而不是创建通用文档资源层。

## 4. Clash / Mihomo

### 4.1 Schema 基线

Clash/Mihomo 改动以最新 `vendor/meta-json-schema` 为字段参考。代理类型入口：

```text
vendor/meta-json-schema/src/modules/config/proxies.json
```

协议字段：

```text
vendor/meta-json-schema/src/modules/adapter/outbound/<protocol>.json
```

截至 schema `88d5239`，`proxies.json` 包含 26 个已知 type。不要在文档或测试中固定一个
无人维护的手写数量；应由 schema fixture 和注册表不变量生成或核对。

本地没有 schema 时：

```bash
git clone --depth 1 https://github.com/dongchengjie/meta-json-schema.git vendor/meta-json-schema
```

`vendor/` 不进入主仓库提交。

### 4.2 Descriptor 注册表

`ClashParser` 和 `ClashEmitter` 通过 `src/subio_v2/protocols/` 分发：

- 强类型协议继承 `StructuredProtocolDescriptor`；
- `ClashFieldSpec` 同时驱动 consumed keys、parse、emit 和 required 校验；
- 特殊语义使用 descriptor hook 或 `check()`，不要在 Parser/Emitter 重建协议分支；
- Mihomo-only 但暂不跨平台的已知协议使用显式 passthrough descriptor；
- 未来未知 type 使用动态 `ClashPassthroughNode`，只允许 Mihomo 同方言输出。

`consumed_keys` 只能包含已经写入 IR、并能从同一规格重新生成的字段。未强类型化字段应留给
`extra`，否则会出现“解析时消费、生成时丢失”。

未知 transport 和非 active transport option block 必须完整保留，不能降级为 TCP，也不能
因为提取了一个子字段而删除整个嵌套配置。

### 4.3 新增或完善协议

1. 从最新 schema 和目标平台官方文档建立字段矩阵；
2. 判断字段属于跨平台语义、方言扩展还是同方言 passthrough；
3. 必要时在 `model/nodes.py` 增加 Node/Enum/Settings；
4. 新建或更新 `protocols/<name>.py` descriptor；
5. 在 `protocols/__init__.py` 注册，并同步 capability；
6. 增加 schema round-trip、required、组合字段和跨平台诊断测试；
7. 先跑 example，再跑目标测试和全量测试。

只有需要跨平台转换的协议才值得强类型化。Mihomo-only 协议可以先显式 passthrough；不要把
所有 schema 字段机械复制进 IR。

## 5. Surge

### 5.1 语法与 codec

Surge 代理行不能使用普通 `split(",")`。值可以包含逗号、等号、引号和重复参数。
`src/subio_v2/surge/syntax.py` 负责 tokenizer/serializer，
`src/subio_v2/surge/codecs.py` 负责 keyword、协议、参数集合和 UDP 行为的共享规格。

新增或修改 Surge 协议时：

1. 先更新 `SurgeCodecSpec`；
2. 再实现 Parser/Emitter 语义；
3. 更新 capability 和官方离线 fixture；
4. 运行 `tests/test_subio_v2_surge_codec_invariants.py`。

Codec 注册表用于共享规格和不变量，不要求把所有 Parser/Emitter 逻辑改写成元编程框架。
除非能消除已知错误，不为“纯注册表”进行大规模重写。

### 5.2 UDP 与跨平台协议

UDP 参数必须按协议定义生成，不能仅依据 `BaseNode.udp` 统一输出。HTTP/HTTPS 不支持
`udp-relay`；HTTP/2 CONNECT、SOCKS5、Shadowsocks 和 External 等协议按各自文档处理；
Snell 等协议的 UDP 能力可能由版本派生。

Tailscale、MASQUE 和 Trust Tunnel 是跨平台协议，应使用强类型节点。相同协议名称不代表
两端支持相同 method/profile：

- Tailscale 需要区分登录方式、exit-node 选择和平台运行状态；
- MASQUE 需要区分 forward proxy、CONNECT-IP、`h3-l4proxy`、H2/H3 传输和认证模型；
- Trust Tunnel 的公共认证/TLS 可映射，平台扩展按 capability 诊断。

External Proxy Program 只允许本地 `file` provider 显式设置
`allow_unsafe_external = true`，且只能输出到 Surge。远程来源、伪造授权和跨平台输出必须在
Parser/Capability 两侧失败关闭。

## 6. Stash

Stash 属于 Clash-family，但不是 Mihomo 字段的无差别子集。它需要独立方言上下文：

- `ParserFactory` 应提供 Stash parser，而不是让调用方假设普通 Clash 输入；
- 输入归一化必须发生在 descriptor 前，并记录原始方言；
- Emitter 只生成 Stash 官方字段和值域；
- Mihomo `extra` 不得直接泄漏到 Stash；
- Stash 专属未知字段只在 Stash -> Stash 往返时保留；
- 协议名相同但字段、枚举大小写或认证模型不同的情况必须显式适配。

Stash 支持的实施顺序和具体协议矩阵见 `docs/development_plan.md`。

## 7. Rules 与 Workflow

Ruleset 是数据，不是 Jinja 源码。远程 matcher、policy、comment 中的模板表达式必须按普通
文本输出。模板使用严格未定义变量；provider、parse、artifact 和 upload 的必需步骤失败时，
CLI 返回非零并阻止部分发布。

Artifact 应先全部生成成功，再开始上传。文件写入使用原子替换；日志、异常、命令参数和 Git
配置不得泄露订阅正文、token、age key、密码或私钥。

`allow_conversion_errors = true` 会放行全部 conversion error，只适合已审阅的调试配置。
新增 issue 时应使用稳定 code，为后续按 code allowlist 做准备。

## 8. 测试与提交

先运行示例：

```bash
uv run subio convert example/config.toml --dry-run
```

再运行目标测试，例如 Clash：

```bash
uv run python -m pytest tests/test_subio_v2_parser_clash*.py -v
```

Surge：

```bash
uv run python -m pytest tests/test_subio_v2_*surge*.py -v
```

最后运行全量测试：

```bash
uv run python -m pytest tests/
```

提交前至少检查：

```bash
git diff --check
git status --short
git -C vendor/meta-json-schema status --short
```

按计划一阶段一提交。问题修复的提交正文写明“问题、方案、验证”；新功能的提交正文写明
“功能、实现、验证”。不要把 `vendor/`、生成的 `dist/` 或无关格式化混入提交。
