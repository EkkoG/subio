# SubIO v2 支持矩阵

本文记录当前代码和测试能够证明的输入、输出与协议范围。这里的“支持”表示 SubIO 的 parser、
target codec 和 emitter 能生成目标格式；同名协议的具体 method、transport、认证和字段仍会逐节点
校验。目标客户端理论上支持、但 SubIO 尚无 serializer 或 round-trip 证据的能力不在矩阵内。

## 1. 节点格式

### 1.1 输入

| `provider.type` | 状态 | 输入 |
|---|---|---|
| `mihomo` | 推荐 | 现代 Mihomo YAML 节点 |
| `clash-meta` | 兼容别名 | 与 `mihomo` 完全相同，加载配置时提示替换为 `mihomo` |
| `clash` | 已废弃但仍支持 | 原版 Clash YAML 节点；加载配置时提示改用 `mihomo` |
| `stash` | 支持 | Stash YAML 节点 |
| `surge` | 支持 | Surge Proxy 内容，以及节点实际引用的 Keystore/WireGuard/Tailscale 附件 |
| `sing-box` | 支持 | sing-box JSON 中当前 codec 支持的 `outbounds` 与 `endpoints`；不是完整客户端配置导入 |
| `v2rayn` | 支持 | v2rayN 分享链接/订阅 |
| `subio` | 推荐用于自建节点 | SubIO 节点文件 v2：`version = 2` + `nodes`，支持 TOML、JSON、JSON5、YAML；v1 与旧 `proxies` 明确拒绝，不提供迁移或 fallback |

### 1.2 输出协议

| `artifact.type` | 状态 | 当前协议能力 |
|---|---|---|
| `mihomo` | 推荐 | 26 种当前 schema type：SS、SSR、VMess、VLESS、Trojan、HTTP、SOCKS5、Hysteria、Hysteria2、TUIC、Gost Relay、Snell、WireGuard、SSH、AnyTLS、Mieru、Rematch、Sudoku、MASQUE、TrustTunnel、OpenVPN、Tailscale、ShadowQUIC、Direct、Reject、DNS；未来未知 type 仅允许 Mihomo 同方言保真 |
| `clash-meta` | 兼容别名 | 与 `mihomo` 使用同一 target codec、emitter 和规则输出，加载配置时产生替代提示 |
| `clash` | 已废弃但仍支持 | SS、VMess、Trojan、HTTP、SOCKS5；保持原版 Clash 的独立能力边界 |
| `stash` | 支持 | SS、SSR、VMess、VLESS、Trojan、HTTP、SOCKS5、Snell、WireGuard、Hysteria、Hysteria2、TUIC、SSH、AnyTLS、Direct、Mieru、Juicity、Tailscale、MASQUE、TrustTunnel |
| `surge` | 支持 | SS、VMess、Trojan、HTTP/HTTPS/H2 CONNECT、SOCKS5、Snell、TUIC、Hysteria2、SSH、AnyTLS、WireGuard、Tailscale、MASQUE、TrustTunnel、Direct、Reject、External |
| `sing-box` | 支持 | JSON outbounds：AnyTLS、Block、Direct、HTTP、Hysteria、Hysteria2、Naive、SS、ShadowTLS、Snell、SOCKS、SSH、Trojan、TUIC、VLESS、VMess；endpoints：`openconnect`、`openvpn-client`、`tailscale`、`wireguard` |
| `dae` | 支持 | SS、VMess、VLESS、Trojan、HTTP、SOCKS5、Hysteria2、TUIC、AnyTLS |
| `v2rayn` | 支持 | SS、VMess、VLESS、Trojan、SOCKS5 |

补充约束：

- SubIO v2 可直接构造当前 27 种公开具体 Node IR，不调用 Mihomo parser；`source-passthrough`、
  Surge External 和运行期来源/保真字段不属于该格式，完整契约见 `docs/subio_node_format.md`；
- Stash target codec 当前开放 20 种协议；Stash-only 的 Juicity 不会伪装成 Mihomo 强类型协议；
- 固定 schema 基线中的 Mihomo type 均使用强类型 IR 和结构化 codec；实际数量由 schema fixture
  与 codec registry 不变量核对，不维护独立手写计数；`dns` 只表示
  内部 DNS 模块出站，不扩展为 DNS section 转换；
- Mieru 是 Mihomo/Stash 共享强类型协议，但 Stash 仅接受其官方 TCP profile；
- Tailscale、MASQUE、TrustTunnel 按 selection/profile/transport/auth 分型，不因协议同名而互转；
- sing-box 节点能力固定以官方 v1.14.3 schema/行为为基线，只实现上表 codec。`openvpn-server`、
  `bridge`、`tor`、`selector`、`urltest`、基线后的新增类型和其他未知类型均产生结构化 unsupported
  issue，不视为完整 sing-box 支持或透传能力；
- sing-box Snell 只支持 v4/v6 的已实现字段组合；Block 只对应 `RejectMode.REJECT`。OpenConnect 只接受
  显式 `https://` URL 与有效 authority（可含数字端口），拒绝空白、userinfo、query 和 fragment；
- Surge External 的本地 file provider 默认可 Surge -> Surge 透传；远程 URL 默认忽略，只有
  `allow_unsafe_external = true` 才允许同平台透传；任何来源都不能输出到其他平台；
- 同方言未知安全字段可保真，跨方言未消费字段产生结构化 issue，不直接泄漏到目标。

`artifact.type = "sing-box"` 必须指定 JSON Jinja `template`，可调用
`nodes.outbounds()`、`nodes.endpoints()`，并组合可分享规则集生成完整客户端 JSON。模板负责完整配置
中的其他部分；这不是完整 sing-box 配置导入、全量配置 IR 或无损往返能力。路由规则只输出能够
精确表示的 sing-box client matcher，并使用 sing-box `route` action；不支持的 matcher/option 会产生
conversion issue，默认阻止产物发布。

## 2. 可分享规则集输入

| `ruleset.type` | `behavior` | `format` |
|---|---|---|
| `mihomo` | `classical` | `text`、`yaml` |
| `mihomo` | `domain`、`ipcidr` | `text`、`yaml`、`mrs` |
| `stash` | `classical` | `text`、`yaml` |
| `stash` | `domain`、`ipcidr` | `text`、`yaml`、`mrs` |
| `surge` | `classical` | `text` |
| `surge` | `domain` | `text` |
| `sing-box` | `classical` | `source`（官方 Source JSON v1-v5） |

`type`、`behavior`、`format` 都未声明时，固定使用 `mihomo + classical + text`。SubIO 不根据 URL、
扩展名或解析失败切换 codec。MRS 只承载 domain/ipcidr，不支持 classical；sing-box Source 不接受
SRS 或完整客户端配置。

本地 snippet 使用同一 Mihomo classical grammar，只额外提供参数声明和最外层 policy binding。
`SCRIPT`、脚本快捷方式、脚本 provider 和其他完整配置依赖不会被下载、执行或转换。

### 2.1 解析范围

| 输入方言 | 可进入 RuleSet IR 的 classical 语义 | 规则内选项 |
|---|---|---|
| Mihomo | 官方 classical provider 中除 `RULE-SET`、`SUB-RULE` 外的 predicate、`MATCH`、`AND`/`OR`/`NOT` | 目标 IP 类规则的 `no-resolve`、`src` |
| Stash | 官方 classical provider 的自包含 predicate、`MATCH`、`AND`/`OR`/`NOT` | IP 类规则的 `no-resolve`；任意规则的 `no-track` |
| Surge | 官方 Rule Set 的自包含 predicate、`AND`/`OR`/`NOT`，逻辑嵌套最多 10 层 | `no-resolve`、`extended-matching`、notification 与 `always-capture` 参数 |
| sing-box Source | Source v1-v5 中可无损进入当前 RuleSet IR 的 default/logical matcher | `invert`；IR 无法表达的已知或未来字段整条产生 parse issue |

这里的“自包含”表示 matcher 和 option 都在规则集文件内。Stash/Surge `SCRIPT` 依赖完整配置中的
脚本定义；Stash/Surge `RULE-SET`、Surge `DOMAIN-SET` 依赖其他资源，因此会生成结构化 parse issue
并跳过，不会建立 Script IR 或递归下载依赖。Surge `FINAL` 和 `pre-matching` 不是合法 Rule Set
文件内容，继续拒绝。

### 2.2 IR 规范化

`Predicate` 与 `LogicalExpression` 保留完整 matcher、option、逻辑树和来源行号。转换时执行以下有
明确语义等价关系的 lowering：

- Mihomo `MATCH` 与 Surge `FINAL`；Mihomo/Stash `DST-PORT` 与 Surge `DEST-PORT`；
- Mihomo `NETWORK,tcp|udp` 与 Stash/Surge `PROTOCOL,tcp|udp`；其他 `PROTOCOL` 值不伪装成 Mihomo `NETWORK`；
- Mihomo `SRC-IP-CIDR`、Mihomo `IP-CIDR/IP-CIDR6 + src` 与 Stash/Surge `SRC-IP`；
- Surge/Stash `PROCESS-NAME` 的文件名、通配符、完整路径和 app bundle 前缀语义，与 Mihomo
  `PROCESS-NAME[-WILDCARD]`、`PROCESS-PATH[-WILDCARD]`；
- domain behavior 中 Mihomo/Stash 与 Surge 对前导点的不同含义，以及可精确表示的域名通配符。

不存在可证明等价关系时不猜测近似规则，交给目标 renderer 产生
`ruleset.unsupported-target-rule` 或 `ruleset.unsupported-target-option`。

## 3. 规则输出

现有 renderer 可为 `mihomo`、`clash`、`stash`、`surge` 和 `dae` 模板生成带 policy 的规则片段；
`clash-meta` 是 `mihomo` 的兼容别名。sing-box 规则只在完整客户端 JSON 模板中输出为 `route.rules`；
不提供节点-only JSON 或独立 Source ruleset artifact。目标无法表示的规则类型、option 或逻辑表达式会生成
结构化 conversion issue，并在未显式放行时阻止 staging、上传和 manifest 发布。

| 目标 | 输出边界 |
|---|---|
| `mihomo` / `clash-meta` | Mihomo 官方规则、options 和高级逻辑；不接收 User-Agent、URL 等 Mihomo 无对应语义的规则 |
| `stash` | Stash 官方自包含规则、`no-track` 和高级逻辑 |
| `surge` | Surge 官方自包含规则、Rule Set 内合法 options 和高级逻辑 |
| `clash` | 原版 Clash 的有限规则子集；不继承 Mihomo 新规则 |
| `dae` | 现有 domain/IP/fallback 模板片段子集 |
| sing-box JSON template | 必须通过完整客户端 JSON 模板输出；规则集 callable 生成 `route.rules` 对象数组，不提供节点-only 或独立 Source/SRS 产物 |

### 3.1 Surge Policy Groups 边界

SubIO v2 不建立 `[Proxy Group]` 的通用 IR。Surge `select`、`url-test`、`fallback`、
`load-balance`、`smart` 和 `subnet` 组，以及 `policy-path`、`include-*` 和组级
`underlying-proxy`，继续由目标模板维护；SubIO 不解析组成员、策略选择或循环语义。
节点自身的 `underlying-proxy` 可以引用模板中已有的静态组名，但 SubIO 不校验该组是否存在、
成员是否有效或是否形成循环。

## 4. 兼容性

### 4.1 convert 参数化生成

`subio convert CONFIG --param NAME=VALUE` 可重复传入最多 32 个字面参数，按第一个 `=` 分割，
保留空值、空白、Unicode 与后续符号，不做 URL 解码。无声明时为 string，`artifact.params` 可补充
integer/boolean、默认值和约束；同一输入按每个 artifact 独立归一化，不传选项也应用各自默认值。
参数化源范围与 GET 相同，最终模板使用相同的不可变 `params`。CLI 无 token 认证，`token` 仍为保留名。
非法或缺失引用在发布前失败；完整生成成功后才入队上传和发布，`--dry-run` 仍写本地产物。
参数化转换只记录安全类别/错误码/计数；manifest 逐输出记录源哈希与实际解析/选择计数，不含参数值。
产物与上传结果包含绑定值，命令行值可能进入 shell 历史与进程列表。

### 4.2 可选 GET 渲染

| 能力 | 当前范围 |
|---|---|
| 服务入口 | 可选 `server` extra；`subio serve CONFIG [--host 127.0.0.1] [--port 8000] [--log-level info] [--refresh-interval 300] [--max-snapshot-age 900]`；可绑定其他网卡、`0.0.0.0` 或 IPv6 |
| 认证 | URL 中唯一 `token`，来自 `SUBIO_RENDER_TOKEN`；无需附加头，一个 token 授权全部已配置 artifact |
| 参数化源 | 显式 `parameterized = true` 的本地 `mihomo` / `clash-meta` / `clash` YAML 与 `subio` v2 TOML/JSON/JSON5/YAML |
| 参数值 | 无需逐个声明，默认 string；`artifact.params` 可补充 integer/boolean、默认值或约束；引用缺失参数返回 400，token 仅用于鉴权 |
| 输出 | `GET /subscription/<file_name>` 直接使用已有输出文件名；固定 `user`、批量 `users` 展开后的单文件及 Age 均支持 |
| 生成策略 | 所有现有 artifact 类型沿用静态生成策略；全局或 artifact 级 `allow_conversion_errors`、`allow_empty` 生效，显式放行的转换错误记录安全 WARNING |
| 资源快照 | 启动/后台准备静态节点、规则/snippet、未绑定参数化文档和模板；warm GET 无源 I/O、源解码或静态解析，每次请求使用一个完整版本 |
| 刷新与过期 | interval 默认 300 秒，完成后等待，不重叠；max age 默认 900 秒；均为正整数且 max age >= interval；monotonic 年龄从成功轮次开始时计量，失败不更新，过期返回 503 |
| 就绪与错误 | 至少一个输出准备成功可启动，未就绪路由 503，全部未就绪则安全启动失败；返回 ParseResult ERROR/fatal_result 属成功获取并更新年龄，由既有 artifact 策略决定是否拒绝，默认 422 |
| 模板 | 可信最终 Jinja 获得不可变 `params`；有限内存命名空间含现有 loader 枚举名称及配置根模板，不递归目录 symlink 查找 helper；provider 只支持一次标量替换，不执行 Jinja |
| 缓存与更新 | 服务仅内存快照，远程磁盘缓存/stale fallback 关闭；`remote.cache` 保持静态 CLI 策略；本地源/snippet/模板成功刷新后更新，配置/token 须重启 |
| 并发与关闭 | 一个独立刷新 worker、四个渲染 worker；取消/断连不提前释放实际工作名额，关闭等待实际线程结束，无硬性期限 |
| 服务日志 | UTC 时间、生命周期、准备/刷新、请求状态/耗时、错误码和安全异常类别；`--log-level` 为 debug/info/warning/error/critical，默认 info；所有级别均不记录 URL/参数、token、源路径或结果 |
| HTTP 副作用 | 无文件发布、上传、manifest、请求报告、参数或结果持久化；不缓存目标编码结果 |

远程 provider、Stash/Surge/sing-box/link 输入不支持源参数化；query 不能改变文档结构、键、源路径、
URL、配置的根模板、target 或用户选择。原生 v2 字段/节点与目标校验仍生效，参数化不会扩大协议矩阵或建立
完整客户端 IR。无法忠实表示的 URI authority、Surge/dae 等目标值仍被编码器拒绝；默认返回 422，
显式允许转换错误时可返回其余可生成内容。请求鉴权、参数输入和结构检查始终执行，URL 不能修改生成策略。
获取、空正文、解密/解码等异常不替换旧快照；已有版本可服务到过期，成功刷新后自动恢复。
独立 provider/根模板故障按 artifact 隔离，全部配置 rulesets 和本地 snippets 仍是共享依赖。
模板的 fallback/ignore-missing 只跳过真正不存在的名称；捕获时发现但无法读取/解码的文件被访问时返回
固定 500，未使用的坏 helper 不阻断其他 artifact。可信模板仍可执行程序行为，没有严格执行期限。

`check/inspect` 不接受 `--param`，参数化源配置仍于 provider/ruleset I/O 前拒绝，包括全部有默认值的情况。
普通源的最终模板也可使用自身 params 默认值，引用缺失值会阻止发布；无声明和输入时 params 为空 mapping。源替换只覆盖节点子树标量，
YAML 循环和会产生 tuple 的 `!!pairs` / `!!omap` 拒绝。部署、编码、限额和 GET 凭据暴露风险见
[GET 渲染指南](get_rendering.md) 与 [离线示例](../example/render/README.md)。

### 4.3 既有配置与接口

- CLI 命令、已有 provider/ruleset/artifact 配置结构、模板 callable 和输出文件组织不变；
- 新配置应使用 `mihomo`；旧 `clash-meta` 配置继续工作并产生配置级替代提示，内部 issue
  target 统一为 `mihomo`；
- `clash` 继续表示原版 Clash，并在 provider/artifact 配置级产生废弃提示；它不会自动升级为
  Mihomo，也不会获得 Mihomo-only 能力；
- 模板名、artifact 文件名和上传文件名中的 `clash` 是用户自定义文本，不自动重命名；
- Stash 节点输入新增 `provider.type = "stash"`，现有配置无需修改；
- `provider.type = "subio"` 只接受 `version = 2` + `nodes` 和 snake_case 原生字段；v1 与顶层
  `proxies` 返回结构化 ERROR，不回退到 Mihomo parser；
- Parser/Emitter 结构化结果不提供通用文档资源 API；Surge Keystore 和命名 section
  仅作为节点附件随成功节点流转；
- `EmissionResult.emitted_policy_names` 已移除；Python API 消费者应从 `supported_nodes` 读取成功
  节点名称，模板上下文使用 `extras["template_context"]`；
- 为避免生成目标官方不接受的字段，部分旧 Stash 输出会被裁剪或拒绝。这是无效输出修正，不是
  对有效配置格式的兼容性破坏。
