# SubIO v2 支持矩阵

本文记录当前代码和测试能够证明的输入、输出与协议范围。这里的“支持”表示 SubIO 的 parser、
capability 和 emitter 能生成目标格式；同名协议的具体 method、transport、认证和字段仍会逐节点
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
| `v2rayn` | 支持 | v2rayN 分享链接/订阅 |
| `subio` | 推荐用于自建节点 | SubIO 节点文件 v1：`version` + `nodes`，支持 TOML、JSON、JSON5、YAML；旧 `proxies` 仅作 Mihomo-compatible 迁移入口并产生 WARNING |

### 1.2 输出协议

| `artifact.type` | 状态 | 当前协议能力 |
|---|---|---|
| `mihomo` | 推荐 | 26 种当前 schema type：SS、SSR、VMess、VLESS、Trojan、HTTP、SOCKS5、Hysteria、Hysteria2、TUIC、Gost Relay、Snell、WireGuard、SSH、AnyTLS、Mieru、Rematch、Sudoku、MASQUE、TrustTunnel、OpenVPN、Tailscale、ShadowQUIC、Direct、Reject、DNS；未来未知 type 仅允许 Mihomo 同方言保真 |
| `clash-meta` | 兼容别名 | 与 `mihomo` 使用同一 capability、emitter 和规则输出，加载配置时产生替代提示 |
| `clash` | 已废弃但仍支持 | SS、VMess、Trojan、HTTP、SOCKS5；保持原版 Clash 的独立能力边界 |
| `stash` | 支持 | SS、SSR、VMess、VLESS、Trojan、HTTP、SOCKS5、Snell、WireGuard、Hysteria、Hysteria2、TUIC、SSH、AnyTLS、Direct、Mieru、Juicity、Tailscale、MASQUE、TrustTunnel |
| `surge` | 支持 | SS、VMess、Trojan、HTTP/HTTPS/H2 CONNECT、SOCKS5、Snell、TUIC、Hysteria2、SSH、AnyTLS、WireGuard、Tailscale、MASQUE、TrustTunnel、Direct、Reject、External |
| `dae` | 支持 | SS、VMess、VLESS、Trojan、HTTP、SOCKS5、Hysteria2、TUIC、AnyTLS |
| `v2rayn` | 支持 | SS、VMess、VLESS、Trojan、SOCKS5 |

补充约束：

- SubIO v1 可直接构造当前 27 种公开具体 Node IR，不调用 Mihomo parser；`source-passthrough`、
  Surge External 和运行期来源/保真字段不属于该格式，完整契约见 `docs/subio_node_format.md`；
- Stash capability 当前为 20 种协议；Stash-only 的 Juicity 不会伪装成 Mihomo 强类型协议；
- 固定 schema 基线中的 26 种 Mihomo type 均使用强类型 IR 和结构化 descriptor；`dns` 只表示
  内部 DNS 模块出站，不扩展为 DNS section 转换；
- Mieru 是 Mihomo/Stash 共享强类型协议，但 Stash 仅接受其官方 TCP profile；
- Tailscale、MASQUE、TrustTunnel 按 selection/profile/transport/auth 分型，不因协议同名而互转；
- Surge External 的本地 file provider 默认可 Surge -> Surge 透传；远程 URL 默认忽略，只有
  `allow_unsafe_external = true` 才允许同平台透传；任何来源都不能输出到其他平台；
- 同方言未知安全字段可保真，跨方言未消费字段产生结构化 issue，不直接泄漏到目标。

## 2. 可分享规则集输入

| `ruleset.type` | `behavior` | `format` |
|---|---|---|
| `mihomo` | `classical` | `text`、`yaml` |
| `mihomo` | `domain`、`ipcidr` | `text`、`yaml`、`mrs` |
| `stash` | `classical` | `text`、`yaml` |
| `stash` | `domain`、`ipcidr` | `text`、`yaml`、`mrs` |
| `surge` | `classical` | `text` |
| `surge` | `domain` | `text` |

`type`、`behavior`、`format` 都未声明时，固定使用 `mihomo + classical + text`。SubIO 不根据 URL、
扩展名或解析失败切换 codec。MRS 只承载 domain/ipcidr，不支持 classical。

本地 snippet 使用同一 Mihomo classical grammar，只额外提供参数声明和最外层 policy binding。
`SCRIPT`、脚本快捷方式、脚本 provider 和其他完整配置依赖不会被下载、执行或转换。

### 2.1 解析范围

| 输入方言 | 可进入 RuleSet IR 的 classical 语义 | 规则内选项 |
|---|---|---|
| Mihomo | 官方 classical provider 中除 `RULE-SET`、`SUB-RULE` 外的 predicate、`MATCH`、`AND`/`OR`/`NOT` | 目标 IP 类规则的 `no-resolve`、`src` |
| Stash | 官方 classical provider 的自包含 predicate、`MATCH`、`AND`/`OR`/`NOT` | IP 类规则的 `no-resolve`；任意规则的 `no-track` |
| Surge | 官方 Rule Set 的自包含 predicate、`AND`/`OR`/`NOT`，逻辑嵌套最多 10 层 | `no-resolve`、`extended-matching`、notification 与 `always-capture` 参数 |

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

现有 renderer 可为 `mihomo`、`clash`、`stash`、`surge` 和 `dae` 模板生成规则片段；
`clash-meta` 是 `mihomo` 的兼容别名。SubIO 没有新增独立的规则集输出 artifact；规则仍通过
现有模板 callable 绑定 policy。目标无法表示的规则类型、option 或逻辑表达式会生成结构化
conversion issue，并在未显式放行时阻止发布。

| 目标 | 输出边界 |
|---|---|
| `mihomo` / `clash-meta` | Mihomo 官方规则、options 和高级逻辑；不接收 User-Agent、URL 等 Mihomo 无对应语义的规则 |
| `stash` | Stash 官方自包含规则、`no-track` 和高级逻辑 |
| `surge` | Surge 官方自包含规则、Rule Set 内合法 options 和高级逻辑 |
| `clash` | 原版 Clash 的有限规则子集；不继承 Mihomo 新规则 |
| `dae` | 现有 domain/IP/fallback 模板片段子集 |

## 4. 兼容性

- CLI 命令、已有 provider/ruleset/artifact 配置结构、模板 callable 和输出文件组织不变；
- 新配置应使用 `mihomo`；旧 `clash-meta` 配置继续工作并产生配置级替代提示，内部 issue
  target 统一为 `mihomo`；
- `clash` 继续表示原版 Clash，并在 provider/artifact 配置级产生废弃提示；它不会自动升级为
  Mihomo，也不会获得 Mihomo-only 能力；
- 模板名、artifact 文件名和上传文件名中的 `clash` 是用户自定义文本，不自动重命名；
- Stash 节点输入新增 `provider.type = "stash"`，现有配置无需修改；
- 旧 `provider.type = "subio"` + 顶层 `proxies` 继续按 Mihomo 字段语义解析并产生迁移 WARNING；
  新文件应使用 `version = 1` + `nodes` 和 snake_case 原生字段；
- Parser/Emitter 结构化结果不提供通用文档资源 API；Surge Keystore 和命名 section
  仅作为节点附件随成功节点流转；
- `EmissionResult.emitted_policy_names` 已移除；Python API 消费者应从 `supported_nodes` 读取成功
  节点名称，模板上下文使用 `extras["template_context"]`；
- 为避免生成目标官方不接受的字段，部分旧 Stash 输出会被裁剪或拒绝。这是无效输出修正，不是
  对有效配置格式的兼容性破坏。
