# SubIO v2 开发指南

本文档描述当前有效的架构边界和扩展方法。历史实现过程见 `docs/v2_fix_plan.md` 和
`docs/surge_support_plan.md`；后续工作以 `docs/development_plan.md` 为准。

## 1. 项目边界

SubIO v2 只转换两类内容：

1. 代理节点；
2. Mihomo、Stash、Surge 官方定义的可独立分享规则集。

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

节点主线：

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

规则集主线以 `docs/development_plan.md` 阶段 1～2 的契约为准，完成后只保留这一条语义路径：

```text
Config / local snippet
  -> Mihomo / Stash / Surge RuleSetInputCodec
  -> HeadlessRuleSet
  -> ParameterizedRuleSet (policy binding)
  -> existing rule renderer
  -> Template / Artifact
  -> Uploader
```

两条主线共享方言上下文、结构化 issue、模板和发布边界，但不共享 Node IR 与 RuleSet IR，
也不扩展为完整平台配置 AST。

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
| `src/subio_v2/workflow/` | provider、规则集、模板、artifact 和上传事务 |
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

`ParseResult.resources` 和 `EmissionResult.emitted_resource_keys` 目前仅为兼容保留，不得承载新的
完整文档资源设计。`EmissionResult.emitted_policy_names` 仍被 Workflow 用作 Surge 模板桥接，
必须等平台模板上下文下沉后再移除。

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

### 3.4 方言上下文

`docs/development_plan.md` 阶段 1 和阶段 4 完成后，节点和规则集使用同一个轻量 `DialectContext`
契约描述来源或目标方言。来源与目标分别传入上下文实例，不创建 `RuleSetSourceContext`、
`NodeDialectContext` 或平台专属 context 等平行类型。

- RuleSet input codec 负责最先定义并使用该契约；
- Node Parser/Emitter、现有规则 renderer 和 extension 消费检查随后接入同一契约；
- 通用 hook 只规定 normalizer、descriptor 和 emitter 的调用位置；
- Stash 等平台的具体字段映射只在对应 parser/emitter 阶段实现；
- 后续阶段不得重新设计已经验收的 RuleSet codec 接口。

## 4. Clash / Mihomo

### 4.1 Schema 基线

Clash/Mihomo 改动以 `vendor/meta-json-schema` 为字段参考。当前计划的可复现审查基线是
`88d5239`；开始新的 schema 对齐工作时应先更新到当时最新版本，记录新 commit，并同步离线快照。
代理类型入口：

```text
vendor/meta-json-schema/src/modules/config/proxies.json
```

协议字段：

```text
vendor/meta-json-schema/src/modules/adapter/outbound/<protocol>.json
```

审查基线 `88d5239` 的 `proxies.json` 包含 26 个已知 type。不要维护脱离 commit 的手写数量；
数量和字段应由带来源 commit 的 schema fixture 与注册表不变量生成或核对。

复现当前计划基线：

```bash
git clone https://github.com/dongchengjie/meta-json-schema.git vendor/meta-json-schema
git -C vendor/meta-json-schema checkout --detach 88d5239
```

需要核对更新时再 fetch 最新提交，并在计划与 fixture 中显式记录新 hash。`vendor/` 不进入主仓库提交。

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

### 7.1 可分享规则集

以下内容是 `docs/development_plan.md` 已锁定、但尚未实施完成的目标契约。当前宽松 parser 的
额外行为不构成兼容承诺，也不得写入新的用户示例。

SubIO 只解析 Mihomo、Stash 和 Surge 官方定义的可独立分享规则集，不解析完整配置中的
`rules`、`[Rule]`、script provider 或其他外部依赖资源。

统一术语如下：

- `RuleSetInputCodec`：按来源方言、format 和 behavior 解析输入；
- `HeadlessRuleSet`：不带 policy 的有序规则语义；
- `ParameterizedRuleSet`：在规则语义外增加参数声明和逐条 policy binding；
- rule renderer：现有目标配置片段生成器，不新增对称的规则集输出 artifact。

远程 `[[ruleset]]` 通过 `type = "mihomo" | "stash" | "surge"` 声明输入方言；未声明 `type`
时精确定义为 `mihomo + classical + text`。显式声明方言时使用对应 codec，不根据 URL、文件名
或解析失败结果切换方言。不得保留 legacy parser、宽松 fallback 或根据逗号位置猜 policy。

Mihomo 和 Stash 的 YAML/text 支持 `domain`、`ipcidr`、`classical`；MRS 当前只支持 `domain`、
`ipcidr`。远程加载必须保留原始 bytes，由 codec 选择文本解码或 MRS 解码；运行时不得依赖外部
Mihomo CLI。Surge 输入只覆盖外部 Rule Set、Domain Set 和已抽取的 inline Ruleset 内容。

本地 snippet 是参数化的 Mihomo classical 规则集：第一行声明参数，后续规则不写 policy 时绑定
第一个参数，`{{ name }}` 只能引用已声明参数，`DIRECT` 等值是固定 policy。移除 binding 后，
规则本身必须通过同一 Mihomo classical grammar，不能把 snippet 当作任意文本或通用 Jinja 源码。

远程 matcher、policy、comment 中的模板表达式一律作为普通数据。Stash 或 Surge 规则集中出现的
`SCRIPT,name` 只代表完整配置中的外部依赖，必须产生结构化 unsupported issue；不得下载、保存、
执行或转换脚本。

“输出保持兼容”只表示现有目标平台、模板 callable、policy 参数、artifact 文件组织和文本格式
不新增另一套 API；已经确认会生成错误字段或静默丢失语义的行为必须按计划修正，不能用 golden 固化。

### 7.2 Workflow

模板使用严格未定义变量；provider、parse、artifact 和 upload 的必需步骤失败时，CLI 返回非零并
阻止部分发布。

Artifact 应先全部生成成功，再开始发布。每个本地文件使用原子替换，但多文件整批不保证原子，
远程上传也不属于同一个全局事务。日志、异常、命令参数和 Git 配置不得泄露订阅正文、token、
age key、密码或私钥。

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
