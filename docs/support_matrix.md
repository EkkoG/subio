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
| `subio` | 支持 | SubIO 本地节点格式 |

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

- Stash capability 当前为 20 种协议；Stash-only 的 Juicity 不会伪装成 Mihomo 强类型协议；
- Mieru 是 Mihomo/Stash 共享强类型协议，但 Stash 仅接受其官方 TCP profile；
- Tailscale、MASQUE、TrustTunnel 按 selection/profile/transport/auth 分型，不因协议同名而互转；
- Surge External 只接受本地 file provider 的显式授权，且不能输出到其他平台；
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

## 3. 规则输出

现有 renderer 可为 `mihomo`、`clash`、`stash`、`surge` 和 `dae` 模板生成规则片段；
`clash-meta` 是 `mihomo` 的兼容别名。SubIO 没有新增独立的规则集输出 artifact；规则仍通过
现有模板 callable 绑定 policy。目标无法表示的规则类型、option 或逻辑表达式会生成结构化
conversion issue，并在未显式放行时阻止发布。

## 4. 兼容性

- CLI 命令、已有 provider/ruleset/artifact 配置结构、模板 callable 和输出文件组织不变；
- 新配置应使用 `mihomo`；旧 `clash-meta` 配置继续工作并产生配置级替代提示，内部 issue
  target 统一为 `mihomo`；
- `clash` 继续表示原版 Clash，并在 provider/artifact 配置级产生废弃提示；它不会自动升级为
  Mihomo，也不会获得 Mihomo-only 能力；
- 模板名、artifact 文件名和上传文件名中的 `clash` 是用户自定义文本，不自动重命名；
- Stash 节点输入新增 `provider.type = "stash"`，现有配置无需修改；
- Parser/Emitter 结构化结果不提供通用文档资源 API；Surge Keystore 和命名 section
  仅作为节点附件随成功节点流转；
- `EmissionResult.emitted_policy_names` 已移除；Python API 消费者应从 `supported_nodes` 读取成功
  节点名称，模板上下文使用 `extras["template_context"]`；
- 为避免生成目标官方不接受的字段，部分旧 Stash 输出会被裁剪或拒绝。这是无效输出修正，不是
  对有效配置格式的兼容性破坏。
