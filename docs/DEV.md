# SubIO v2 开发指南

本文档描述当前有效的架构边界和扩展方法。当前能力见 `docs/support_matrix.md`；
`docs/development_plan.md`、`docs/v2_fix_plan.md` 和 `docs/surge_support_plan.md` 只记录已完成的
设计与实施过程。

## 1. 项目边界

SubIO v2 只转换两类内容：

1. 代理节点；
2. Mihomo、Stash、Surge 官方定义的可独立分享规则集。

协议和字段实现必须基于当前工作区、本文、support matrix、官方资料和可复现测试独立完成；不得
对照、复制、cherry-pick 或反向推断其他分支的实现。缺少官方资料的平台只维持现有 serializer
与 contract 已证明的能力，不从其他平台的同名字段推导支持。

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
  -> pure transforms (filter / rename / dialer relation)
  -> TargetValidationService.encode_node (semantic + target codec validation/encode)
  -> Target Emitter
  -> Artifact
  -> Uploader
```

规则集主线已经收口为唯一语义路径：

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
| `src/subio_v2/core/` | 跨平台节点语义、共享设置、结构化结果和目标无关校验 |
| `src/subio_v2/infrastructure/` | Age、remote loader 和日志等低层外部副作用 |
| `src/subio_v2/adapters/` | 格式 catalog、target validation、checked emitter 和各格式 family adapter |
| `src/subio_v2/protocols/` | Clash-family 协议 codec、逐目标约束和 Stash 字段合同 |
| `src/subio_v2/adapters/links/` | v2rayN/dae document adapter 与逐协议 link codec |
| `src/subio_v2/adapters/clash_family/` | Clash-family parser、emitter、共享字段和嵌套 transport/smux 辅助函数 |
| `src/subio_v2/adapters/surge/` | Surge document adapter、词法、codec 规格、安全门禁和节点附件 |
| `src/subio_v2/adapters/catalog.py` | 格式名称、alias/deprecation、输入/输出 factory 和公共 target policy |
| `src/subio_v2/protocols/values.py` | 不带 target 语义的共享协议值域常量 |
| `src/subio_v2/adapters/target.py` | 从实际 target codec 派生支持并返回 checked encode result |
| `src/subio_v2/rules/` | 可分享规则集 grammar、输入 codec、不可变 output dialect、IR runtime 和 renderer |
| `src/subio_v2/workflow/` | typed config、provider/artifact 编排、模板和发布事务 |
| `vendor/meta-json-schema/` | Mihomo 字段参考；仅本地依赖，不提交 |

`adapters.catalog.get_parser()` 和 `adapters.catalog.get_emitter()` 每次返回新实例。Parser、Emitter、Uploader 的可变状态不得
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

- `BaseNode.source_context` 是节点及其未建模字段的唯一来源方言；
- `BaseNode.extra` 当前用于 Clash-family codec 未建模字段的同方言往返；
- `TransportSettings.extra` 保存 `ws-opts`、`grpc-opts` 等嵌套块中的未建模字段；
- `SourcePassthroughNode.raw` 只保存真正未知 YAML type 或 Surge External 的完整来源记录；
- `BaseNode.source_extensions[<dialect>]` 保存来源方言专属字段和节点附件。

Clash-family 输入先经过 `pre_descriptor_normalize()`，共享 codec 输出后再经过
`post_descriptor_emit()`。未知字段只有来源和目标 dialect 相同时才能合并；跨方言未消费字段必须
产生 `conversion.unconsumed-source-field`，不能依赖 target validation 日志后仍写入结果。

这些数据不是通用语义。Emitter 只能消费属于自己目标方言的扩展；跨方言未消费内容必须
产生 `conversion.unconsumed-source-field`，不能直接合并进目标配置。

`ParseResult` 只承载节点和解析问题，`EmissionResult` 只承载输出、成功节点、问题和模板上下文；
不提供通用文档资源旁路。`EmissionResult.emitted_policy_names` 已删除；成功生成的节点名称以
`supported_nodes` 为准，平台模板数据只能放在 `extras["template_context"]`，Workflow 不读取
Emitter 私有兼容字段。

### 3.3 节点附件

Surge 节点附件定义在 `src/subio_v2/adapters/surge/resources.py`。约束如下：

1. Parser 的 Keystore/section catalog 只在一次输入解析期间存在；
2. 只复制当前节点实际引用的条目；
3. 未引用内容不进入 `ParseResult`；
4. Emitter 只从成功生成的最终节点收集附件；
5. 同键同值去重，同键异值只淘汰后出现的冲突节点；
6. issue、日志和 `repr` 不得包含私钥、密码、auth-key 或完整 section；
7. 通用 workflow 不得导入或合并 Surge 附件。

其他平台若出现同类需求，应复用“节点所有权”原则，而不是创建通用文档资源层。

### 3.4 方言上下文

节点和规则集使用同一个轻量 `DialectContext` 契约描述来源或目标方言。来源与目标分别传入上下文
实例，不创建 `RuleSetSourceContext`、`NodeDialectContext` 或平台专属 context 等平行类型。

- RuleSet input codec 负责最先定义并使用该契约；
- Node Parser/Emitter、现有规则 renderer 和 extension 消费检查随后接入同一契约；
- 通用 hook 只规定 normalizer、codec 和 emitter 的调用位置；
- Stash 等平台的具体字段映射只在对应 parser/emitter 方言模块实现；
- 新工作不得重新设计已经验收的 RuleSet codec 接口。

### 3.5 原生 SubIO 节点格式

`provider.type = "subio"` 只有一条原生输入路径：

```text
version = 2 + nodes
  -> serialization decoder
  -> SubioNodeCodec
  -> concrete Node IR
```

原生路径使用 `Protocol.value` 和 snake_case IR 字段，不调用 `parse_clash()`，也不接受单字段
Mihomo alias。`src/subio_v2/adapters/subio/schema.py` 是公开字段 allowlist 与确定性 JSON Schema 的
来源；`schemas/subio-node-v2.schema.json` 是提交仓库的机器可读快照。修改其中任一侧时必须运行
schema 生成命令，并由测试证明快照、协议注册表和 runtime 字段一致。

JSON Schema 只描述结构、允许字段、基础类型和 enum，不为组合校验建立复杂 conditional 生成器。
required、范围和协议组合以 `validate_node()` 及 codec validation 为准；用户文档必须明确这
两层职责，不能把 schema 单独描述为完整语义验证器。

公开格式只包含 concrete Node、公开 dataclass 嵌套设置和受限 mapping。Reality、ECH、Brutal、
AmneziaWG、Shadowsocks plugin、Snell obfs 与 header mapping 的 native key/type 契约集中在
`subio_format/schema.py`；codec 负责把 snake_case native key 归一化为现有 Node IR 的内部键。
`source_context`、`source_provider`、
`original_name`、`extra`、`source_extensions`、`transport.extra`、`SourcePassthroughNode` 和 Surge
External 固定排除。`SSH.keystore_id`、`TLSSettings.client_cert_ref` 和 Tailscale
`interactive_login` 依赖本机 Surge 资源或状态，也固定排除。不要为了原生输入再建立一套 protocol
codec；native codec 从 `ProtocolSpec` 取得 Node class，但不能借用 Clash 字段规格。

目标无关语义由 `src/subio_v2/core/validation.py` 校验，`TargetValidationService.encode_node()` 随后调用实际
target codec 完成支持、约束检查和编码。含 `users` 的原生节点按每个声明用户应用 override 后校验，允许凭据只存在于用户级；
native override 字段由逐协议 `ProtocolSpec.user_override_fields` 明确列出，并且必须仍是 Node
模型与通用 clone 机制支持的字段，不能再依靠全局字段名交集推断。新协议或字段进入 Node IR 时，
必须明确选择加入 terminal native policy 或排除，并更新 schema、用户文档和注册表不变量测试。

原生格式目前只有输入 codec，不增加 `artifact.type = "subio"`。版本兼容规则和公开字段说明见
`docs/subio_node_format.md`。

## 4. Clash / Mihomo

### 4.1 平台命名边界

公开配置和内部注册表使用以下固定契约：

| 名称 | 状态 | 语义 |
|---|---|---|
| `mihomo` | 规范名称 | 现代 Mihomo YAML |
| `clash-meta` | 兼容别名 | 与 `mihomo` 完全相同，配置级提示替换为规范名称 |
| `clash` | 已废弃但仍支持 | 原版 Clash YAML，保持独立 codec 和规则范围 |

所有 parser、emitter 和规则 renderer 的公开入口必须先通过
`src/subio_v2/adapters/catalog.py` 规范化。内部 codec registry、`DialectContext` 和结构化
issue 只使用 `mihomo` 规范名称；不得在 target constraints、规则输出表或业务代码中
新增独立 `clash-meta` authority，也不得增加散落的 `platform == "clash-meta"` 分支。

`clash` 不得规范化为 `mihomo`。废弃状态只影响配置级提示和文档推荐，不得放宽原版 Clash 的
协议、transport、cipher、feature 或规则能力。`ClashParser`、`ClashEmitter` 和
`src/subio_v2/adapters/clash_family/` 是 Clash-family 共享实现名，不因公开平台命名而机械搬迁；模板文件名、
artifact 文件名和上传文件名中的 `clash` 也不自动改写。

`clash-meta` 不是废弃平台，也不改变转换结果；Workflow 只在 provider/artifact 配置级各提示
一次改用 `mihomo`。Parser、Emitter、target codec 和逐节点转换不得重复提示。

### 4.2 Schema 基线

Clash/Mihomo 改动以 `vendor/meta-json-schema` 为字段参考。已归档项目计划的可复现审查基线是
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

复现该审查基线：

```bash
git clone https://github.com/dongchengjie/meta-json-schema.git vendor/meta-json-schema
git -C vendor/meta-json-schema checkout --detach 88d5239
```

需要核对更新时再 fetch 最新提交，并在审计记录与 fixture 中显式记录新 hash。`vendor/` 不进入
主仓库提交。

### 4.3 Clash codec 注册表

`ClashParser` 和 `ClashEmitter` 通过 `src/subio_v2/protocols/` 分发：

- 强类型协议继承 `StructuredClashProtocolCodec`；
- `ClashFieldSpec` 同时驱动 consumed keys、parse、emit 和 required 校验；
- 特殊语义使用 codec hook 或 `check()`，不要在 document Parser/Emitter 重建协议分支；
- 固定 schema 中的全部已知 type 都使用结构化 codec，即使当前只有 Mihomo 能输出；
- 未来未知 type 不进入 codec 注册表，由 Parser 创建 `SourcePassthroughNode`，且只能回到
  `source_context` 所记录的规范来源平台。

`consumed_keys` 只能包含已经写入 IR、并能从同一规格重新生成的字段。未强类型化字段应留给
`extra`，否则会出现“解析时消费、生成时丢失”。

目标支持由实际 target codec 派生；不建立独立 capability snapshot 或手写平台协议集合。协议的组合条件
与对应 target codec 共置，编码和诊断通过同一 checked encode result 返回。

未知 transport 和非 active transport option block 必须完整保留，不能降级为 TCP，也不能
因为提取了一个子字段而删除整个嵌套配置。

### 4.4 新增或完善协议

1. 从官方文档建立字段矩阵；没有官方资料的平台只维持现有 serializer/contract 已证明的能力；
2. 判断字段属于跨平台语义、来源 preservation 还是平台附件；
3. 在 semantic Node/共享 value object 增加字段，并在唯一 `ProtocolSpec` 明确 terminal native
   public/excluded 与 user override 决策；
4. 更新实际支持该字段的 Clash/Surge/Link target codec；目标支持由实际 codec 派生，不新增全局
   target protocol set；
5. 为字段增加 parse/emit、值域/组合、same-dialect preservation 和 cross-target issue tests；
6. 若终态 native contract 公开该字段，重新生成 v2 schema 并更新 `docs/subio_node_format.md`；
7. 先跑 example、targeted/contract tests，再跑全量测试。

官方 schema 已定义且影响运行的稳定语义应进入具体 Node，即使当前只有一个目标平台支持；目标不支持
时由 target codec 产生精确 issue。纯序列化信息和真正未知的新字段留在同方言 `extra`，不要把所有
schema 元数据机械复制进 IR。

## 5. Surge

### 5.1 语法与 codec

Surge 代理行不能使用普通 `split(",")`。值可以包含逗号、等号、引号和重复参数。
`src/subio_v2/adapters/surge/syntax.py` 负责 tokenizer/serializer，
`src/subio_v2/adapters/surge/codecs.py` 负责 keyword、协议、参数集合、UDP 行为、parser/emitter callable 和
Surge target constraints 的唯一 executable codec。

新增或修改 Surge 协议时：

1. 先更新对应 `SurgeCodecSpec`；
2. 在 `surge/parsers.py` 和 `surge/emitters.py` 实现 callable，并绑定到同一 spec；
3. 更新官方离线 fixture 和 codec invariant；不要把 Surge constraints 放回 Clash protocol codec；
4. 运行 `tests/test_subio_v2_surge_codec_invariants.py`。

Codec registry 是实际 parser/emitter/target 支持入口，不允许再建立平行 handler map；协议特殊资源仍由
document adapter 按节点附件所有权处理。

分享链接位于 `src/subio_v2/adapters/links/codecs/`。每种协议拥有独立 `LinkCodec`；支持输入的 codec 同时声明
scheme parser、dae/v2rayN 输出能力和 target constraints，均由 codec target registration 派生。不要在 document parser、
dae emitter 或 v2rayN emitter 中新增 scheme/protocol 分支。

### 5.2 UDP 与跨平台协议

UDP 参数必须按协议定义生成，不能仅依据 `BaseNode.udp` 统一输出。HTTP/HTTPS 不支持
`udp-relay`；HTTP/2 CONNECT、SOCKS5、Shadowsocks 和 External 等协议按各自文档处理；
Snell 等协议的 UDP 能力可能由版本派生。

Tailscale、MASQUE 和 Trust Tunnel 是跨平台协议，应使用强类型节点。相同协议名称不代表
两端支持相同 method/profile：

- Tailscale 需要区分登录方式、exit-node 选择和平台运行状态；
- MASQUE 需要区分 forward proxy、CONNECT-IP、`h3-l4proxy`、H2/H3 传输和认证模型；
- Trust Tunnel 的公共认证/TLS 可映射，平台扩展按 target codec 诊断。

External Proxy Program 的本地 `file` provider 默认允许 Surge -> Surge 同平台透传；远程 URL
provider 默认忽略，只有显式设置 `allow_unsafe_external = true` 才允许同平台透传并记录高可见度
安全 WARNING。该开关只对远程 Surge provider 有意义，External 跨平台始终 WARNING 后跳过。
直接调用 Parser 时，`source_kind = "unknown"` 按不可信输入处理，只有显式 `local` 使用本地语义。

## 6. Stash

Stash 属于 Clash-family，但不是 Mihomo 字段的无差别子集。它需要独立方言上下文：

- `get_parser("stash")` 提供 Stash parser，调用方不应把 Stash 输入当作普通 Clash；
- 输入归一化必须发生在 codec 前，并记录原始方言；
- Emitter 只生成 Stash 官方字段和值域；
- Mihomo `extra` 不得直接泄漏到 Stash；
- Stash 专属未知字段只在 Stash -> Stash 往返时保留；
- 协议名相同但字段、枚举大小写或认证模型不同的情况必须显式适配。

Stash 当前开放 20 种协议。具体输入、目标协议和跨平台限制见 `docs/support_matrix.md`。

## 7. Rules 与 Workflow

### 7.1 可分享规则集

以下是当前已经实施并由测试固定的规则集契约。旧宽松 parser、URL/扩展名嗅探、policy 猜测和
脚本处理路径均不属于兼容 API。

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
Mihomo CLI 或系统 `zstd`。MRS 使用进程内 `zstandard` 和带输入/解压上限的 data-only decoder，
校验内嵌 behavior、长度、trie/range 结构和尾部数据。Surge 输入只覆盖外部 Rule Set、Domain Set
和已抽取的 inline Ruleset 内容。

本地 snippet 是参数化的 Mihomo classical 规则集：第一行声明参数，后续规则不写 policy 时绑定
第一个参数，`{{ name }}` 只能引用已声明参数，`DIRECT` 等值是固定 policy。移除 binding 后，
规则本身必须通过同一 Mihomo classical grammar，不能把 snippet 当作任意文本或通用 Jinja 源码。

远程 matcher、policy、comment 中的模板表达式一律作为普通数据。Stash 或 Surge 规则集中出现的
`SCRIPT,name` 只代表完整配置中的外部依赖，必须产生结构化 unsupported issue；不得下载、保存、
执行或转换脚本。

规则 IR 使用 `Predicate` 和 `LogicalExpression` 表示三平台自包含规则。来源方言只在 matcher 或
option 语义确实不同处参与 lowering，例如 `MATCH`/`FINAL`、`DST-PORT`/`DEST-PORT`、
`NETWORK`/`PROTOCOL`、`SRC-IP-CIDR`/`SRC-IP`，以及 Stash/Surge `PROCESS-NAME` 的文件名、
通配符、完整路径和 app bundle 前缀模式。Stash `no-track` 只输出回 Stash；Surge
`extended-matching`、notification 和 capture 参数只输出到 Surge。无法证明等价时生成稳定 issue，
不得因 rule type 字符串相同而直接透传成不同语义。

“输出保持兼容”只表示现有目标平台、模板 callable、policy 参数、artifact 文件组织和文本格式
不新增另一套 API；已经确认会生成错误字段或静默丢失语义的行为必须修正，不能用 golden 固化。

### 7.2 Workflow

运行期责任边界如下：

- `ConfigLoader` 读取 TOML/YAML/JSON/JSON5，`ConfigValidator` 在构造 runtime config 前完成语义验证；
- `RunConfig` 暴露 typed `ProviderConfig`、`ArtifactConfig`、`UploaderConfig` records；
- `ProviderLoaderService` 负责 provider IO、remote dedup、Age/UTF-8、parser 和 `workflow.transforms`；
- `ArtifactGenerationService` 负责 emitter、用户覆盖、filter、issue policy、template/ruleset、Age，并只返回
  `ArtifactDraft` 与 `ArtifactUploadRequest`；不直接访问 uploader 或本地文件；
- `ArtifactPublisher` 负责本地文件发布事务；
- `WorkflowEngine` 是薄 run service，只规定 ruleset/provider/artifact/publish/upload 的顺序和失败边界；
  artifact builder 返回 typed draft/result，所有 issue 在单一 artifact gate 决策后才进入 staging，
  完整生成成功后才由入口统一校验并入队 upload request。

application service 只通过 `adapters.catalog.get_parser()`、`adapters.catalog.get_emitter()` 和窄结果类型访问 adapter，不导入具体
Surge/Clash/link 实现。一次 run 的 loader、parser、emitter 和 uploader 状态不得泄漏到下一次运行。

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

SubIO 原生节点格式：

```bash
uv run python -m pytest tests/test_subio_v2_parser_subio.py -v
uv run python -m subio_v2.adapters.subio.schema schemas/subio-node-v2.schema.json
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

按能够独立解释、独立验证和方便 review 的边界及时提交，避免特大提交，不机械要求一阶段只有一个
提交。问题修复的提交正文写明“问题、方案、验证”；新功能的提交正文写明“功能、实现、验证”。
不要把 `vendor/`、生成的 `dist/` 或无关格式化混入提交。
