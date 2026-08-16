# SubIO 原生节点文件格式 v1

这份文档是 `provider.type = "subio"` 的完整用户格式说明。目标是让你只看这一份文档，就能写出
可被 SubIO 直接解析为 Node IR 的节点文件。

它只描述代理节点，不包含代理组、DNS section、脚本、规则、模板、artifact 或上传配置。SubIO 原生
节点格式也不是 Mihomo YAML 的别名：字段统一使用 snake_case，协议类型使用 SubIO 规范名称。

机器可读结构位于 `schemas/subio-node-v1.schema.json`。Schema 检查字段、基础类型、公开 enum 和严格
嵌套对象；协议必填组合、数值关系及目标平台能力仍由 SubIO runtime 检查。

## 1. 接入 provider

本地文件：

```toml
[[provider]]
name = "self-hosted"
type = "subio"
file = "nodes.toml"
```

远程文件：

```toml
[[provider]]
name = "remote-nodes"
type = "subio"
url = "https://example.com/nodes.json"
```

如果远程或本地内容经过 age 加密，在 provider 上配置私钥；不存在 `age = true`：

```toml
[[provider]]
name = "private-nodes"
type = "subio"
url = "https://example.com/nodes.toml.age"
age_secret_key = "AGE-SECRET-KEY-1..."
```

通用 provider 处理仍可使用 `[provider.filters]`、`[provider.rename]` 和 `dialer_proxy`。当前 provider
没有 `override` 或 `relation` 选项。节点内的 `users` 是 artifact 用户白名单与凭据覆盖，不是 provider
配置项。SubIO 原生格式目前只有输入 codec，没有 `artifact.type = "subio"`。

## 2. 顶层结构与序列化

最小 TOML 文件：

```toml
version = 1

[[nodes]]
name = "HK-01"
type = "shadowsocks"
server = "hk.example.com"
port = 8388
cipher = "aes-256-gcm"
password = "secret"
```

顶层只允许两个字段：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `version` | integer | 是 | 固定为 `1` |
| `nodes` | object[] | 是 | 节点数组，可为空 |

固定规则：

- 支持 TOML、YAML、JSON、JSON5；它们只是同一对象模型的不同序列化；
- `type` 使用规范名称，例如 `shadowsocks`，不接受 Mihomo 的 `ss`；
- 所有结构字段使用 snake_case，例如 `skip_cert_verify`；HTTP header 名称等用户数据不改名；
- 可选字段通过省略表达；显式 `null` 不属于 v1；
- 未知字段、未知类型、错误类型和错误 enum 都产生结构化解析错误；
- 单个节点错误不会丢弃同一文件中的其他合法节点；
- 文档示例以 TOML 为主；YAML/JSON/JSON5 使用相同字段名和值。

TOML 嵌套对象写成 `[nodes.tls]`，嵌套对象数组写成 `[[nodes.peers]]`。YAML 中的同一最小节点是：

```yaml
version: 1
nodes:
  - name: HK-01
    type: shadowsocks
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
```

## 3. 公共节点字段

除 `direct`、`dns`、`reject`、`rematch`、`tailscale` 和使用 `port_range` 的 `mieru` 外，大多数协议
要求有效的 `server` 与 `port`。

| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `name` | string | 不允许省略 | 节点名称，不能为空 |
| `type` | string enum | 不允许省略 | 第 6 节的规范协议名 |
| `server` | string 或 string[] | `null` | 远程地址；通常写单个域名或 IP，数组只用于能表达多地址的目标 |
| `port` | integer | `null` | 远程端口；需要端点时为 `1..65535` |
| `udp` | boolean | `true` | 请求 UDP 能力；协议或目标仍可拒绝 |
| `ip_version` | string enum | `null` | `dual`、`ipv4`、`ipv6`、`ipv4-prefer`、`ipv6-prefer` |
| `tfo` | boolean | `false` | TCP Fast Open |
| `mptcp` | boolean | `false` | Multipath TCP |
| `dialer_proxy` | string | `null` | 通过另一个节点建立底层连接 |
| `interface_name` | string | `null` | 绑定出站接口 |
| `routing_mark` | integer | `null` | Linux 路由标记，主要由 Mihomo-family 表达 |
| `users` | object | `null` | artifact 用户白名单与覆盖，见第 5 节 |
| `shadow_tls` | object | 禁用 | 公共 ShadowTLS 设置，见 4.4 |
| `surge_options` | object | 空对象 | Surge policy 公共选项，见 4.5 |

`tls`、`transport`、`smux` 不是公共字段，只能用于第 6 节明确列出的协议。内部字段
`source_context`、`source_provider`、`original_name`、`extra`、`source_extensions`、
`transport.extra` 和 `source-passthrough` 永远不能写入原生文件。

## 4. 共享对象

### 4.1 `tls`

```toml
[nodes.tls]
enabled = true
server_name = "example.com"
alpn = ["h2", "http/1.1"]
skip_cert_verify = false
client_fingerprint = "chrome"
```

<!-- nested-fields:TLSSettings -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `enabled` | boolean | `false`，部分协议强制为 `true` | 是否启用/应用 TLS 设置 |
| `server_name` | string | `null` | TLS SNI |
| `alpn` | string[] | `null` | ALPN 列表 |
| `skip_cert_verify` | boolean | `false` | 跳过证书链验证 |
| `client_fingerprint` | string | `null` | uTLS 客户端指纹 |
| `reality_opts` | object | `null` | Reality 参数，见 4.6 |
| `ech_opts` | object | `null` | ECH 参数，见 4.6 |
| `certificate` | string | `null` | PEM 客户端证书或目标支持的证书值 |
| `private_key` | string | `null` | PEM 客户端私钥或目标支持的私钥值 |
| `sni_disabled` | boolean | `false` | 明确禁用 SNI；主要用于 Surge 语义 |
| `verify_name` | string | `null` | 只改变证书 DNSName 验证目标，不改变 SNI |
| `certificate_sha256` | string | `null` | 服务端证书 SHA-256 指纹 |
<!-- /nested-fields -->

`client_cert_ref` 是 Surge 本地状态引用，不属于可分享的 v1 字段。

### 4.2 `transport`

```toml
[nodes.transport]
network = "ws"
path = "/proxy"
headers = { Host = "example.com" }
max_early_data = 2048
early_data_header_name = "Sec-WebSocket-Protocol"
```

<!-- nested-fields:TransportSettings -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `network` | string enum | `tcp` | `tcp`、`ws`、`http`、`h2`、`grpc`、`xhttp` |
| `path` | string 或 string[] | `null` | WS/H2/XHTTP path；HTTP 可使用 path 数组 |
| `headers` | object | `null` | header 名到 string 或 string[] 的映射 |
| `host` | string 或 string[] | `null` | H2/XHTTP host |
| `method` | string | `GET` | HTTP transport 方法 |
| `grpc_service_name` | string | `null` | gRPC service name |
| `xhttp_mode` | string | `null` | XHTTP mode |
| `max_early_data` | integer | `null` | WebSocket early data 最大字节数 |
| `early_data_header_name` | string | `null` | WebSocket early data header 名 |
<!-- /nested-fields -->

### 4.3 `smux`

```toml
[nodes.smux]
enabled = true
protocol = "smux"
max_connections = 4
min_streams = 4
max_streams = 0
padding = false

[nodes.smux.brutal_opts]
enabled = true
up = 20
down = 100
```

<!-- nested-fields:SmuxSettings -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `enabled` | boolean | `false` | 启用 sing-mux |
| `protocol` | string enum | `smux` | `smux`、`yamux`、`h2mux` |
| `max_connections` | integer | `4` | 最大底层连接数；与 `max_streams` 是不同控制模式 |
| `min_streams` | integer | `4` | 打开新连接前的最小流数 |
| `max_streams` | integer | `0` | 单连接最大流数；非零时不要同时依赖前两项 |
| `padding` | boolean | `false` | 启用复用填充 |
| `brutal_opts` | object | `null` | `enabled: boolean`、`up: integer`、`down: integer`，速率单位 Mbps |
<!-- /nested-fields -->

### 4.4 `shadow_tls`

<!-- nested-fields:ShadowTLSSettings -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `password` | string | `null` | 写入后启用 ShadowTLS |
| `server_name` | string | `null` | 伪装 TLS server name |
| `version` | integer enum | `2` | `1`、`2`、`3` |
<!-- /nested-fields -->

### 4.5 `surge_options`

这些字段只描述 Surge policy 公共行为；转到不支持的目标时会产生 capability issue。

<!-- nested-fields:SurgePolicyOptions -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `allow_other_interface` | boolean | `null` | Surge `allow-other-interface` |
| `dns_follow_interface` | boolean | `null` | Surge `dns-follow-interface` |
| `no_error_alert` | boolean | `null` | Surge `no-error-alert` |
| `hybrid` | string | `null` | Surge hybrid 参数原值 |
| `tos` | string | `null` | Surge IP TOS 参数原值 |
| `ecn` | string | `null` | Surge ECN 参数原值 |
| `block_quic` | string | `null` | Surge `block-quic` 参数原值 |
| `test_url` | string | `null` | 单节点测试 URL |
| `test_timeout` | integer | `null` | 测试超时 |
| `test_udp` | string | `null` | Surge UDP 测试参数原值 |
<!-- /nested-fields -->

### 4.6 严格 mapping 对象

以下对象不接受未声明字段。原生文件使用左侧 snake_case 键，codec 会转换为 Node IR 内部需要的键。

`tls.reality_opts`：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `public_key` | string | 是 | Reality 公钥 |
| `short_id` | string | 否 | Reality short id |

`tls.ech_opts`：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `enable` | boolean | 否 | 启用 ECH |
| `config` | string | 否 | Base64 ECHConfigList；省略时可由目标自行查询 |
| `query_server_name` | string | 否 | DNS 查询 ECH 配置时使用的域名 |

WireGuard `amnezia_wg_option`：

- integer：`jc`、`jmin`、`jmax`、`s1`、`s2`、`s3`、`s4`、`itime`；
- string：`h1`、`h2`、`h3`、`h4`、`i1`、`i2`、`i3`、`i4`、`i5`、`j1`、`j2`、`j3`。

Shadowsocks `plugin_opts` 的允许字段：

| 字段组 | 字段与类型 |
|---|---|
| 通用 | `mode: string`、`host: string`、`path: string`、`password: string`、`username: string`、`alpn: string[]` |
| TLS | `tls: boolean`、`ech_opts: object`、`fingerprint: string`、`certificate: string`、`private_key: string`、`skip_cert_verify: boolean`、`verify_name: string` |
| HTTP | `headers: object`、`mux: boolean`、`v2ray_http_upgrade: boolean`、`v2ray_http_upgrade_fast_open: boolean` |
| Restls | `version_hint: string`、`restls_script: string` |
| ShadowTLS | `version: integer` |
| kcptun 字符串 | `key`、`crypt`、`mode` |
| kcptun 整数 | `conn`、`autoexpire`、`scavengettl`、`mtu`、`ratelimit`、`sndwnd`、`rcvwnd`、`datashard`、`parityshard`、`dscp`、`nodelay`、`interval`、`resend`、`nc`、`sockbuf`、`smuxver`、`smuxbuf`、`framesize`、`streambuf`、`keepalive` |
| kcptun 布尔 | `nocomp`、`acknodelay` |

`plugin` 只接受 `obfs`、`v2ray-plugin`、`shadow-tls`、`restls`、`jls`、`gost-plugin`、
`kcptun`。不同 plugin 只使用与其有关的字段；目标是否支持该 plugin 在 conversion 阶段检查。

Snell `obfs_opts` 允许：`mode`、`host`、`password`、`fingerprint`、`certificate`、`private_key`、
`skip_cert_verify`、`verify_name`、`version`、`version_hint`、`restls_script`、`username`、`alpn`。
其中 `mode` 常用 `http`、`tls`、`shadow-tls`、`restls`、`jls`。

### 4.7 WireGuard peer 与 Sudoku HTTP mask

`wireguard.peers[]`：

<!-- nested-fields:WireguardPeer -->
| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `server` | string | 是 | peer 地址 |
| `port` | integer | 是 | peer 端口 |
| `public_key` | string | 是 | peer 公钥 |
| `allowed_ips` | string[] | 是 | 通过此 peer 路由的 CIDR |
| `preshared_key` | string | 否 | 预共享密钥 |
| `reserved` | integer[] | 否 | WireGuard reserved bytes |
<!-- /nested-fields -->

`sudoku.httpmask`：

<!-- nested-fields:SudokuHTTPMaskSettings -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `disable` | boolean | `null` | 禁用 HTTP mask |
| `mode` | string enum | `null` | `legacy`、`stream`、`poll`、`auto`、`ws` |
| `tls` | boolean | `null` | HTTP mask 使用 TLS |
| `host` | string | `null` | HTTP host |
| `path_root` | string | `null` | path 根路径 |
| `multiplex` | string enum | `null` | `off`、`auto`、`on` |
<!-- /nested-fields -->

## 5. 多用户节点

`users` 把 artifact 用户名映射到该用户的端点或凭据覆盖。没有 `users` 的节点对所有 artifact 用户
可见；写了 `users` 的节点只进入名单中对应用户的产物。

```toml
version = 1

[[nodes]]
name = "ssh-personal"
type = "ssh"
server = "ssh.example.com"
port = 22
username = "default"

[nodes.users.alice]
username = "alice"
private_key = "alice-private-key"

[nodes.users.bob]
username = "bob"
password = "bob-password"
```

每个用户应用覆盖后必须形成合法节点。默认节点可以只提供公共部分；如果某个用户缺少必要凭据，错误
路径会指向 `nodes[<index>].users.<user>.<field>`。每个协议的精确白名单写在对应协议小节；
`type`、`tls`、`transport`、`smux`、`users` 等结构字段不能覆盖。

## 6. 协议参考

每个协议小节只列协议专属字段；公共字段仍按第 3 节生效。表中“省略时”描述模型默认；标为必填或
条件必填的空值会在 runtime 校验失败。所有示例都是完整 v1 文档，并由测试通过真实 codec 解析。

### 6.1 `anytls`

<!-- subio-example:anytls -->
```toml
version = 1

[[nodes]]
name = "anytls"
type = "anytls"
server = "anytls.example.com"
port = 443
password = "secret"

[nodes.tls]
server_name = "anytls.example.com"
```
<!-- /subio-example -->

TLS 默认启用；写 `[nodes.tls]` 时不需要重复写 `enabled = true`。

<!-- protocol-fields:anytls -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `password` | string | 空字符串（校验失败） | 必填认证密码 |
| `tls` | object | `enabled = true` | TLS 设置 |
| `reuse` | boolean | `true` | 连接复用；`false` 只在部分目标可表达 |
| `idle_session_check_interval` | integer | `null` | 空闲会话检查间隔 |
| `idle_session_timeout` | integer | `null` | 空闲会话超时 |
| `min_idle_session` | integer | `null` | 最小空闲会话数 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`。

### 6.2 `direct`

<!-- subio-example:direct -->
```toml
version = 1

[[nodes]]
name = "DIRECT-v4"
type = "direct"
ip_version = "ipv4"
```
<!-- /subio-example -->

不需要 `server` 或 `port`。它是一个可命名的直连出站，不是代理组中的保留字替换。

<!-- protocol-fields:direct -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `smux` | object | 禁用 | 复用设置；大多数目标不会对 DIRECT 使用 |
<!-- /protocol-fields -->

可按用户覆盖：无。

### 6.3 `dns`

<!-- subio-example:dns -->
```toml
version = 1

[[nodes]]
name = "DNS-Out"
type = "dns"
```
<!-- /subio-example -->

不需要端点。它表示 Mihomo-family 的内部 DNS outbound，不是完整配置中的 DNS section。

<!-- protocol-fields:dns -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `smux` | object | 禁用 | 复用设置 |
<!-- /protocol-fields -->

可按用户覆盖：无。

### 6.4 `gost-relay`

<!-- subio-example:gost-relay -->
```toml
version = 1

[[nodes]]
name = "GOST"
type = "gost-relay"
server = "gost.example.com"
port = 443
username = "alice"
password = "secret"
forward = true

[nodes.tls]
enabled = true
server_name = "gost.example.com"
```
<!-- /subio-example -->

<!-- protocol-fields:gost-relay -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `forward` | boolean | `false` | GOST forward 模式 |
| `mux` | boolean | `false` | GOST 自身 mux；与 `smux` 不是同一机制 |
| `username` | string | `null` | 可选用户名 |
| `password` | string | `null` | 可选密码 |
| `tls` | object | 禁用 | TLS 设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`username`。

### 6.19 `ssh`

<!-- subio-example:ssh -->
```toml
version = 1

[[nodes]]
name = "SSH"
type = "ssh"
server = "ssh.example.com"
port = 22
username = "root"
private_key = "-----BEGIN OPENSSH PRIVATE KEY-----..."
private_key_passphrase = "optional-passphrase"
host_key_algorithms = ["ssh-ed25519"]
server_fingerprints = ["SHA256:example"]
```
<!-- /subio-example -->

`username` 必填；`password` 与 `private_key` 至少提供一个。`private_key_passphrase` 只在私钥加密时
需要。`keystore_id` 是 Surge 本地引用，不属于原生 v1。

<!-- protocol-fields:ssh -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `username` | string | 空字符串（校验失败） | 必填用户名 |
| `password` | string | `null` | 密码认证 |
| `private_key` | string | `null` | 私钥认证 |
| `private_key_passphrase` | string | `null` | 私钥口令 |
| `host_key` | string[] | `null` | 允许的主机公钥值 |
| `host_key_algorithms` | string[] | `null` | 允许的 host key 算法 |
| `idle_timeout` | integer | `null` | 空闲超时 |
| `server_fingerprints` | string[] | `null` | 服务端指纹白名单 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`private_key`、`private_key_passphrase`、`server`、`username`。

### 6.20 `sudoku`

<!-- subio-example:sudoku -->
```toml
version = 1

[[nodes]]
name = "Sudoku"
type = "sudoku"
server = "sudoku.example.com"
port = 443
key = "secret"
aead_method = "chacha20-poly1305"
padding_min = 10
padding_max = 30
table_type = "prefer_entropy"
multiplex = "auto"

[nodes.httpmask]
mode = "auto"
tls = true
host = "cdn.example.com"
path_root = "/proxy"
multiplex = "on"
```
<!-- /subio-example -->

`padding_min`/`padding_max` 都必须在 `0..100`，且 max 不小于 min。`custom_table` 与
`custom_tables[]` 中每个字符串必须恰好由 2 个 `x`、2 个 `p`、4 个 `v` 组成。

<!-- protocol-fields:sudoku -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `key` | string | 空字符串（校验失败） | 必填密钥 |
| `aead_method` | string enum | `chacha20-poly1305` | `chacha20-poly1305`、`aes-128-gcm`、`none` |
| `padding_min` | integer | `10` | 最小 padding 百分比/级别 |
| `padding_max` | integer | `30` | 最大 padding 百分比/级别 |
| `table_type` | string enum | `prefer_entropy` | `entropy`、`prefer_entropy`、`ascii`、`prefer_ascii`、`up_ascii_down_entropy`、`up_entropy_down_ascii` |
| `enable_pure_downlink` | boolean | `true` | 纯下行模式；设为 `false` 时 AEAD 不能为 `none` |
| `multiplex` | string enum | `off` | `off`、`auto`、`on` |
| `httpmask` | object | `null` | 新 HTTP mask 对象，见 4.7 |
| `custom_table` | string | `null` | 单个自定义 table |
| `custom_tables` | string[] | `null` | 多个自定义 table |
| `legacy_http_mask` | boolean | `null` | 旧 `http-mask` 开关 |
| `legacy_http_mask_mode` | string enum | `null` | `legacy`、`stream`、`poll`、`auto`、`ws` |
| `legacy_http_mask_tls` | boolean | `null` | 旧 HTTP mask TLS |
| `legacy_http_mask_host` | string | `null` | 旧 HTTP mask host |
| `legacy_path_root` | string | `null` | 旧 path root |
| `legacy_http_mask_strategy` | string enum | `null` | `random`、`post`、`websocket` |
| `legacy_http_mask_multiplex` | string enum | `null` | `off`、`auto`、`on` |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`port`、`server`。

### 6.21 `tailscale`

<!-- subio-example:tailscale -->
```toml
version = 1

[[nodes]]
name = "Tailscale"
type = "tailscale"
hostname = "subio-node"
auth_key = "tskey-auth-example"
control_url = "https://controlplane.tailscale.com"
ephemeral = true
accept_routes = true
exit_node = "100.64.0.10"
exit_node_allow_lan_access = true
```
<!-- /subio-example -->

不使用传统 `server`/`port`。原生格式只能携带可分享的登录材料，不能写 Surge
`interactive_login` 本地状态引用。`exit_node` 的自动选择值在 Mihomo、Stash、Surge 间语义不同，
转换时会严格检查。

<!-- protocol-fields:tailscale -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `hostname` | string | `null` | Tailscale 设备名 |
| `auth_key` | string | `null` | 可分享 auth key；Surge 输出通常需要 |
| `control_url` | string | `null` | control plane URL |
| `state_dir` | string | `null` | Mihomo state directory |
| `ephemeral` | boolean | `false` | 临时节点 |
| `accept_routes` | boolean | `false` | 接受 tailnet routes |
| `exit_node` | string | `null` | exit node 地址/名称或平台 selector |
| `exit_node_auto_fallback` | boolean | `false` | Stash 未指定 exit-node 时的自动 fallback 语义 |
| `exit_node_allow_lan_access` | boolean | `false` | 使用 exit node 时允许 LAN |
| `derp_only` | boolean | `false` | Surge DERP-only |
| `auto_add_magic_dns_rule` | boolean | `null` | Surge 自动添加 MagicDNS 规则 |
| `idle_keepalive` | integer | `null` | Surge idle keepalive |
| `prefer_ipv6` | boolean | `false` | Surge 优先 IPv6 |
| `dns_servers` | string[] | `null` | Surge DNS 服务器 |
| `mtu` | integer | `null` | Tailscale MTU |
| `smux` | object | 禁用 | Mihomo sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`auth_key`。

### 6.22 `trojan`

<!-- subio-example:trojan -->
```toml
version = 1

[[nodes]]
name = "Trojan-WS"
type = "trojan"
server = "trojan.example.com"
port = 443
password = "secret"

[nodes.tls]
enabled = true
server_name = "trojan.example.com"

[nodes.transport]
network = "ws"
path = "/proxy"
headers = { Host = "cdn.example.com" }
```
<!-- /subio-example -->

<!-- protocol-fields:trojan -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `password` | string | 空字符串（校验失败） | 必填密码 |
| `tls` | object | 禁用 | TLS 设置；正常 Trojan 节点通常启用 |
| `transport` | object | `network = "tcp"` | 传输层设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`。

### 6.23 `trusttunnel`

<!-- subio-example:trusttunnel -->
```toml
version = 1

[[nodes]]
name = "TrustTunnel-QUIC"
type = "trusttunnel"
server = "trust.example.com"
port = 443
username = "alice"
password = "secret"
quic = true
congestion_controller = "bbr"
max_connections = 4
min_streams = 8

[nodes.tls]
server_name = "trust.example.com"
```
<!-- /subio-example -->

TLS 默认启用。`quic` 与 `websocket` 不能同时为 true。`max_streams` 与 `max_connections`/
`min_streams` 属于两种互斥的流控制模式。`headers` 是 Surge Trust Tunnel 的原始 header 字符串，
不是 HTTP header mapping。

<!-- protocol-fields:trusttunnel -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `username` | string | 空字符串（校验失败） | 必填用户名 |
| `password` | string | 空字符串（校验失败） | 必填密码 |
| `headers` | string | `null` | Surge header 参数原值 |
| `max_streams` | integer | `null` | 单连接最大流数 |
| `quic` | boolean | `false` | QUIC transport |
| `websocket` | boolean | `false` | Surge WebSocket transport |
| `health_check` | boolean | `null` | Mihomo health check |
| `congestion_controller` | string | `null` | 拥塞控制器 |
| `cwnd` | integer | `null` | 拥塞窗口 |
| `bbr_profile` | string | `null` | BBR profile |
| `max_connections` | integer | `null` | 最大连接数 |
| `min_streams` | integer | `null` | 打开新连接前的最小流数 |
| `tls` | object | `enabled = true` | TLS 设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`username`。

### 6.24 `tuic`

<!-- subio-example:tuic -->
```toml
version = 1

[[nodes]]
name = "TUIC-v4"
type = "tuic"
server = "tuic.example.com"
port = 443
version = 4
token = "v4-token"

[[nodes]]
name = "TUIC-v5"
type = "tuic"
server = "tuic.example.com"
port = 443
version = 5
uuid = "00000000-0000-0000-0000-000000000005"
password = "v5-password"
ports = "443,8443-8450"
hop_interval = 30

[nodes.tls]
server_name = "tuic.example.com"
alpn = ["h3"]
```
<!-- /subio-example -->

TLS 默认启用。v4 必须只使用 `token`；v5 必须使用 `uuid` + `password`，不能混入 v4 token。
省略 `version` 时 codec 按凭据自动推断。端口跳跃与底层代理的组合由目标 capability 检查。

<!-- protocol-fields:tuic -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `token` | string | `null` | TUIC v4 token |
| `password` | string | `null` | TUIC v5 password |
| `uuid` | string | `null` | TUIC v5 UUID |
| `version` | integer enum | `null`（自动推断） | `4` 或 `5` |
| `ports` | string | `null` | 端口跳跃表达式 |
| `hop_interval` | integer | `null` | 端口跳跃间隔 |
| `tls` | object | `enabled = true` | TLS 设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`token`、`uuid`。

### 6.25 `vless`

<!-- subio-example:vless -->
```toml
version = 1

[[nodes]]
name = "VLESS-Reality"
type = "vless"
server = "vless.example.com"
port = 443
uuid = "00000000-0000-0000-0000-000000000006"
flow = "xtls-rprx-vision"
packet_encoding = "xudp"

[nodes.tls]
enabled = true
server_name = "www.example.com"
client_fingerprint = "chrome"

[nodes.tls.reality_opts]
public_key = "reality-public-key"
short_id = "0123456789abcdef"
```
<!-- /subio-example -->

<!-- protocol-fields:vless -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `uuid` | string | 空字符串（校验失败） | 必填 UUID |
| `flow` | string | `null` | VLESS flow，例如 `xtls-rprx-vision` |
| `tls` | object | 禁用 | TLS/Reality 设置 |
| `transport` | object | `network = "tcp"` | 传输层设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
| `packet_encoding` | string | `null` | packet encoding，例如 `xudp` |
<!-- /protocol-fields -->

可按用户覆盖：`port`、`server`、`uuid`。

### 6.26 `vmess`

<!-- subio-example:vmess -->
```toml
version = 1

[[nodes]]
name = "VMess-WS"
type = "vmess"
server = "vmess.example.com"
port = 443
uuid = "00000000-0000-0000-0000-000000000007"
alter_id = 0
cipher = "auto"
global_padding = false
packet_encoding = "xudp"

[nodes.tls]
enabled = true
server_name = "vmess.example.com"

[nodes.transport]
network = "ws"
path = "/proxy"
headers = { Host = "cdn.example.com" }
```
<!-- /subio-example -->

<!-- protocol-fields:vmess -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `uuid` | string | 空字符串（校验失败） | 必填 UUID |
| `alter_id` | integer | `0` | VMess alterId |
| `cipher` | string | `auto` | VMess security/cipher |
| `global_padding` | boolean | `false` | global padding |
| `vmess_aead` | boolean | `false` | Surge `vmess-aead` 语义 |
| `tls` | object | 禁用 | TLS 设置 |
| `transport` | object | `network = "tcp"` | 传输层设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
| `packet_encoding` | string | `null` | packet encoding，例如 `xudp` |
<!-- /protocol-fields -->

可按用户覆盖：`alter_id`、`cipher`、`port`、`server`、`uuid`。

### 6.27 `wireguard`

<!-- subio-example:wireguard -->
```toml
version = 1

[[nodes]]
name = "WireGuard-Single"
type = "wireguard"
server = "wg.example.com"
port = 51820
private_key = "private-key"
public_key = "peer-public-key"
interface_ip = ["10.0.0.2/32", "fd00::2/128"]
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 25

[nodes.amnezia_wg_option]
jc = 4
jmin = 40
jmax = 70
h1 = "12345678"

[[nodes]]
name = "WireGuard-Multi-Peer"
type = "wireguard"
server = "bootstrap.example.com"
port = 51820
private_key = "private-key"
interface_ip = "10.1.0.2/32"

[[nodes.peers]]
server = "peer-a.example.com"
port = 51820
public_key = "peer-a-public-key"
allowed_ips = ["10.10.0.0/16"]

[[nodes.peers]]
server = "peer-b.example.com"
port = 51820
public_key = "peer-b-public-key"
allowed_ips = ["0.0.0.0/0", "::/0"]
preshared_key = "peer-b-preshared-key"
reserved = [1, 2, 3]
```
<!-- /subio-example -->

`private_key` 必填。单 peer 写法需要顶层 `public_key`；多 peer 写法使用 `peers[]`，每项必须提供
server、port、public_key、allowed_ips。当前 Node IR 仍保留顶层 bootstrap `server`/`port`，因此多 peer
示例也要写这两个公共字段。

<!-- protocol-fields:wireguard -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `private_key` | string | 空字符串（校验失败） | 本地私钥 |
| `public_key` | string | 空字符串 | 单 peer 公钥；使用 `peers` 时可省略 |
| `preshared_key` | string | `null` | 单 peer 预共享密钥 |
| `interface_ip` | string 或 string[] | `null` | IPv4/混合接口 CIDR |
| `interface_ipv6` | string 或 string[] | `null` | 独立 IPv6 接口 CIDR |
| `allowed_ips` | string[] | `null` | 单 peer allowed IP |
| `reserved` | integer[] | `null` | 单 peer reserved bytes |
| `mtu` | integer | `null` | WireGuard MTU |
| `workers` | integer | `null` | worker 数 |
| `persistent_keepalive` | integer | `null` | keepalive 秒数 |
| `amnezia_wg_option` | object | `null` | 严格 AmneziaWG 对象，见 4.6 |
| `peers` | object[] | `null` | 多 peer 列表，见 4.7 |
| `remote_dns_resolve` | boolean | `null` | 远程 DNS 解析 |
| `dns_servers` | string[] | `null` | DNS 服务器 |
| `refresh_server_ip_interval` | integer | `null` | server IP 刷新间隔 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`port`、`preshared_key`、`private_key`、`public_key`、`server`。

## 7. 目标平台兼容性

原生格式能进入 Node IR，不代表每个目标都能输出。典型情况：

- `routing_mark`、部分 SMUX/Brutal 和部分新协议字段主要由 Mihomo-family 表达；
- `surge_options`、`vmess_aead`、Trust Tunnel WebSocket 等是 Surge profile；
- MASQUE、Tailscale、Trust Tunnel 在多个平台同名，但 mode、transport、认证或自动选择语义不同；
- plugin、cipher、transport、协议版本和 TLS 子功能都可能受目标 capability 限制；
- 无法表达的字段会生成字段级 conversion issue，不会因为来自原生格式就静默删除。

默认情况下 conversion ERROR 会阻止 artifact 发布。`allow_conversion_errors = true` 会整体放行，只适合
已经审阅问题的调试配置。目标支持范围见 `docs/support_matrix.md`。

## 8. 错误与排查

| code | 含义 |
|---|---|
| `parse.subio.unsupported-version` | `version` 不是 `1` |
| `parse.subio.invalid-document` | 顶层类型或字段组合错误 |
| `parse.subio.missing-nodes` | 缺少 `nodes` |
| `parse.subio.invalid-node` | `nodes` 中的条目不是对象 |
| `parse.subio.unknown-type` | 未知、来源绑定或不公开的节点类型 |
| `parse.subio.unknown-field` | 顶层、节点、严格对象或 user override 出现未知字段 |
| `parse.subio.invalid-field` | 字段类型、enum、null 或嵌套值错误 |
| `parse.subio.invalid-combination` | 必填项、范围关系或字段组合不合法 |
| `parse.subio.legacy-proxies` | 使用旧 `proxies` Mihomo-compatible 语法的迁移 WARNING |

issue 的 `field` 使用 `nodes[2].tls.server_name` 形式。错误消息不会回显密码、私钥、UUID、auth key、
证书或整个节点对象。

## 9. Legacy `proxies` 迁移

旧 SubIO 文件可能只是 Mihomo proxy 字典的另一种序列化：

```yaml
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
```

这条路径继续按 Mihomo 字段语义解析，并产生一次 `parse.subio.legacy-proxies` WARNING。迁移步骤：

1. 增加 `version: 1`；
2. 将 `proxies` 改为 `nodes`；
3. 将 `ss`、`ssr` 等平台别名改为规范 type；
4. 将连字符字段和平台嵌套块改为本文件的 snake_case 字段；
5. Reality、ECH、plugin、obfs 等严格对象使用 4.6 的规范键；
6. 用 `uv run subio convert example/config.toml --dry-run` 检查解析和 capability issue。

`nodes` 与 `proxies` 不能同时出现。原生节点中也不能逐字段混入 Mihomo alias；兼容只发生在整个旧
文档入口。

## 10. 版本规则

格式 version 与 SubIO 软件版本分离。v1 可以新增向后兼容的可选协议或字段；改变已发布字段类型、
enum、默认语义，或删除/重命名字段，需要新格式 version。内部 Node IR 可以重构，但 v1 codec 必须
保持已发布的输入语义。

### 6.5 `http`

<!-- subio-example:http -->
```toml
version = 1

[[nodes]]
name = "HTTPS-Proxy"
type = "http"
server = "proxy.example.com"
port = 443
username = "alice"
password = "secret"
variant = "https"
headers = { User-Agent = "SubIO" }

[nodes.tls]
enabled = true
server_name = "proxy.example.com"
```
<!-- /subio-example -->

`username` 与 `password` 都省略时表示无认证。`variant = "h2-connect"` 表示 HTTP/2 CONNECT；UDP
还要求目标支持 CONNECT-UDP。

<!-- protocol-fields:http -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `username` | string | `null` | Basic/代理认证用户名 |
| `password` | string | `null` | Basic/代理认证密码 |
| `headers` | object<string,string> | `null` | 额外 HTTP header |
| `variant` | string enum | `auto` | `auto`、`http`、`https`、`h2-connect` |
| `max_streams` | integer | `null` | H2 CONNECT 最大流数 |
| `tls` | object | 禁用 | TLS 设置；`https` 通常同时启用 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`username`。

### 6.6 `hysteria`

<!-- subio-example:hysteria -->
```toml
version = 1

[[nodes]]
name = "Hysteria"
type = "hysteria"
server = "hy.example.com"
port = 443
auth_str = "secret"
up = "20 Mbps"
down = "100 Mbps"

[nodes.tls]
server_name = "hy.example.com"
```
<!-- /subio-example -->

TLS 默认启用。`up`/`down` 保存带单位的速率文本；`up_speed`/`down_speed` 保存整数速率字段，使用哪组
取决于目标。`ports` 与 `hop_interval` 用于端口跳跃。

<!-- protocol-fields:hysteria -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `ports` | string | `null` | 端口范围/跳跃表达式 |
| `hysteria_protocol` | string | `null` | Hysteria protocol 参数 |
| `obfs_protocol` | string | `null` | 旧 obfs protocol 参数 |
| `up` | string | `null` | 带单位上行速率 |
| `down` | string | `null` | 带单位下行速率 |
| `up_speed` | integer | `null` | 整数上行速率 |
| `down_speed` | integer | `null` | 整数下行速率 |
| `auth_str` | string | `null` | 字符串认证值 |
| `auth` | string | `null` | 认证值 |
| `obfs` | string | `null` | 混淆值；目标可能不支持 |
| `hop_interval` | integer | `null` | 端口跳跃间隔 |
| `tls` | object | `enabled = true` | TLS 设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`auth`、`auth_str`、`port`、`server`。

### 6.7 `hysteria2`

<!-- subio-example:hysteria2 -->
```toml
version = 1

[[nodes]]
name = "Hysteria2"
type = "hysteria2"
server = "hy2.example.com"
port = 443
password = "secret"
obfs = "salamander"
obfs_password = "obfs-secret"

[nodes.tls]
server_name = "hy2.example.com"
```
<!-- /subio-example -->

TLS 默认启用。配置 `obfs` 时应同时配置 `obfs_password`；目标 capability 会检查可用混淆模式。

<!-- protocol-fields:hysteria2 -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `password` | string | 空字符串（校验失败） | 必填认证密码 |
| `ports` | string | `null` | 端口范围/跳跃表达式 |
| `hop_interval` | integer | `null` | 端口跳跃间隔 |
| `up` | string | `null` | 上行速率表达式 |
| `down` | string | `null` | 下行速率表达式 |
| `obfs` | string | `null` | 混淆模式 |
| `obfs_password` | string | `null` | 混淆密码 |
| `tls` | object | `enabled = true` | TLS 设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`obfs_password`、`password`、`port`、`server`。

### 6.8 `juicity`

<!-- subio-example:juicity -->
```toml
version = 1

[[nodes]]
name = "Juicity"
type = "juicity"
server = "juicity.example.com"
port = 443
uuid = "00000000-0000-0000-0000-000000000001"
password = "secret"

[nodes.tls]
server_name = "juicity.example.com"
```
<!-- /subio-example -->

TLS 默认启用。当前协议 descriptor 来自 Stash 节点格式；输出到其他平台时按 capability 处理。

<!-- protocol-fields:juicity -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `uuid` | string | 空字符串（校验失败） | 必填 UUID |
| `password` | string | 空字符串（校验失败） | 必填密码 |
| `tls` | object | `enabled = true` | TLS 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`uuid`。

### 6.9 `masque`

<!-- subio-example:masque -->
```toml
version = 1

[[nodes]]
name = "MASQUE-Forward"
type = "masque"
mode = "forward-proxy"
transport = "h3"
server = "masque.example.com"
port = 443
username = "alice"
password = "secret"
connect_uri = "https://masque.example.com/.well-known/masque/udp/"

[[nodes]]
name = "MASQUE-Connect-IP"
type = "masque"
mode = "connect-ip"
transport = "h3"
server = "masque.example.com"
port = 443
private_key = "private"
public_key = "public"
interface_ip = "10.0.0.2/32"

[[nodes]]
name = "MASQUE-H3-L4"
type = "masque"
mode = "h3-l4proxy"
transport = "h3"
server = "masque.example.com"
port = 443
private_key = "private"
public_key = "public"
udp = false
```
<!-- /subio-example -->

认证与密钥由 mode 决定：

- `forward-proxy`：用户名/密码都省略，或两者同时提供；
- `connect-ip`：需要 `private_key`、`public_key`，并至少提供 `interface_ip`/`interface_ipv6` 之一；
- `h3-l4proxy`：需要密钥，且当前 Mihomo profile 不支持 UDP；
- `transport`：Surge forward proxy 使用 `h3`；CONNECT-IP 可使用 `h2` 或 `h3`，具体由目标检查。

<!-- protocol-fields:masque -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `mode` | string enum | `forward-proxy` | `forward-proxy`、`connect-ip`、`h3-l4proxy` |
| `transport` | string | `h3` | MASQUE 传输 profile |
| `connect_uri` | string | `null` | forward proxy URI |
| `username` | string | `null` | Basic 用户名 |
| `password` | string | `null` | Basic 密码 |
| `private_key` | string | `null` | CONNECT-IP/H3-L4 私钥 |
| `public_key` | string | `null` | CONNECT-IP/H3-L4 公钥 |
| `interface_ip` | string | `null` | IPv4 隧道地址 |
| `interface_ipv6` | string | `null` | IPv6 隧道地址 |
| `mtu` | integer | `null` | 隧道 MTU |
| `ports` | string | `null` | 端口跳跃表达式 |
| `hop_interval` | integer | `null` | 端口跳跃间隔 |
| `remote_dns_resolve` | boolean | `false` | 远程 DNS 解析 |
| `dns_servers` | string[] | `null` | 远程 DNS 服务器 |
| `congestion_controller` | string | `null` | 拥塞控制器 |
| `cwnd` | integer | `null` | 初始拥塞窗口 |
| `bbr_profile` | string | `null` | BBR profile |
| `handshake_timeout` | integer | `null` | 握手超时 |
| `tls` | object | `enabled = true` | TLS 设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`private_key`、`public_key`、`server`、`username`。

### 6.10 `mieru`

<!-- subio-example:mieru -->
```toml
version = 1

[[nodes]]
name = "Mieru"
type = "mieru"
server = "mieru.example.com"
port_range = "20000-20100"
transport = "TCP"
username = "alice"
password = "secret"
multiplexing = "MULTIPLEXING_LOW"
handshake_mode = "HANDSHAKE_STANDARD"
```
<!-- /subio-example -->

必须在 `port` 与 `port_range` 中恰好选择一个。`port_range` 格式为 `start-end`，两端均在
`1..65535` 且 start 不大于 end。

<!-- protocol-fields:mieru -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `port_range` | string | `null` | 端口范围，与公共 `port` 二选一 |
| `transport` | string enum | `null`（校验失败） | `TCP` 或 `UDP` |
| `username` | string | 空字符串（校验失败） | 必填用户名 |
| `password` | string | 空字符串（校验失败） | 必填密码 |
| `multiplexing` | string enum | `null` | `MULTIPLEXING_DEFAULT`、`MULTIPLEXING_OFF`、`MULTIPLEXING_LOW`、`MULTIPLEXING_MIDDLE`、`MULTIPLEXING_HIGH` |
| `handshake_mode` | string enum | `null` | `HANDSHAKE_DEFAULT`、`HANDSHAKE_STANDARD`、`HANDSHAKE_NO_WAIT` |
| `traffic_pattern` | string | `null` | Mieru traffic pattern |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`username`。`port_range` 不能按用户覆盖。

### 6.11 `openvpn`

<!-- subio-example:openvpn -->
```toml
version = 1

[[nodes]]
name = "OpenVPN-Password"
type = "openvpn"
server = "vpn.example.com"
port = 1194
ca = "-----BEGIN CERTIFICATE-----..."
username = "alice"
password = "secret"

[[nodes]]
name = "OpenVPN-Certificate"
type = "openvpn"
server = "vpn.example.com"
port = 1194
ca = "-----BEGIN CERTIFICATE-----..."
certificate = "-----BEGIN CERTIFICATE-----..."
private_key = "-----BEGIN PRIVATE KEY-----..."
tls_crypt = "-----BEGIN OpenVPN Static key V1-----..."
```
<!-- /subio-example -->

`ca` 必填。认证有两条合法路径：同时提供 `certificate` 与 `private_key`，或提供 `username`（密码可按
服务端要求省略）。`tls_auth`、`tls_crypt`、`tls_crypt_v2` 最多出现一个。

<!-- protocol-fields:openvpn -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `proto` | string enum | `udp` | `udp`、`udp4`、`tcp`、`tcp-client`、`tcp4`、`tcp4-client` |
| `dev` | string enum | `tun` | 当前只接受 `tun` |
| `cipher` | string enum | `AES-128-GCM` | `AES-128-GCM`、`AES-192-GCM`、`AES-256-GCM`、`AES-CBC`、`AES-128-CBC`、`AES-192-CBC`、`AES-256-CBC`、`CHACHA20-POLY1305` |
| `data_ciphers` | string[] | `null` | 数据加密算法列表，值域同 `cipher` |
| `data_ciphers_fallback` | string | `null` | data-ciphers fallback |
| `auth` | string enum | `SHA256` | `MD5`、`SHA1`、`SHA256`、`SHA384`、`SHA512` |
| `comp_lzo` | string enum | `no` | `yes`、`no`、`adaptive` |
| `ca` | string | 空字符串（校验失败） | 必填 CA 内容或目标支持的 CA 值 |
| `certificate` | string | `null` | 客户端证书，必须与 `private_key` 同时出现 |
| `private_key` | string | `null` | 客户端私钥 |
| `tls_auth` | string | `null` | OpenVPN tls-auth key |
| `key_direction` | string enum | `null` | `0` 或 `1` |
| `tls_crypt` | string | `null` | OpenVPN tls-crypt key |
| `tls_crypt_v2` | string | `null` | OpenVPN tls-crypt-v2 key |
| `username` | string | `null` | 用户名；无证书认证时必填 |
| `password` | string | `null` | 密码 |
| `peer_info` | object<string,string> | `null` | OpenVPN peer-info 键值 |
| `ping` | integer | `0` | ping 间隔 |
| `ping_restart` | integer | `0` | ping-restart 超时 |
| `handshake_timeout` | integer | `0` | 握手超时 |
| `mtu` | integer | `1500` | 隧道 MTU |
| `remote_dns_resolve` | boolean | `false` | 远程 DNS 解析 |
| `dns_servers` | string[] | `null` | DNS 服务器 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`username`。证书、私钥、cipher 和 auth 算法不按用户覆盖。

### 6.12 `reject`

<!-- subio-example:reject -->
```toml
version = 1

[[nodes]]
name = "Reject-Drop"
type = "reject"
mode = "reject-drop"
```
<!-- /subio-example -->

不需要端点。

<!-- protocol-fields:reject -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `mode` | string enum | `reject` | `reject`、`reject-drop`、`reject-no-drop`、`reject-tinygif` |
| `smux` | object | 禁用 | 复用设置 |
<!-- /protocol-fields -->

可按用户覆盖：无。

### 6.13 `rematch`

<!-- subio-example:rematch -->
```toml
version = 1

[[nodes]]
name = "Streaming-Rematch"
type = "rematch"
target_rematch_name = "streaming"
```
<!-- /subio-example -->

不需要端点。`target_rematch_name` 与 `target_sub_rule` 至少出现一个。

<!-- protocol-fields:rematch -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `target_rematch_name` | string | `null` | 目标 rematch 名称 |
| `target_sub_rule` | string | `null` | 目标 sub-rule 名称 |
| `smux` | object | 禁用 | 复用设置 |
<!-- /protocol-fields -->

可按用户覆盖：无。

### 6.14 `shadowquic`

<!-- subio-example:shadowquic -->
```toml
version = 1

[[nodes]]
name = "ShadowQUIC"
type = "shadowquic"
server = "shadowquic.example.com"
port = 443
username = "alice"
password = "secret"
quic_versions = ["h3"]
zero_rtt = true
congestion_controller = "bbr"
bbr_profile = "standard"

[nodes.tls]
server_name = "shadowquic.example.com"
alpn = ["h3"]
```
<!-- /subio-example -->

TLS 默认启用。拥塞控制器允许 `cubic`、`new_reno`、`bbr_meta_v1`、`bbr_meta_v2`、`bbr`；
`bbr_profile` 允许 `standard`、`conservative`、`aggressive`。

<!-- protocol-fields:shadowquic -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `username` | string | `null` | 可选用户名 |
| `password` | string | `null` | 可选密码 |
| `tls` | object | `enabled = true` | TLS 设置 |
| `quic_versions` | string[] | `null` | QUIC 版本列表 |
| `udp_over_stream` | boolean | `false` | UDP over stream |
| `zero_rtt` | boolean | `false` | QUIC 0-RTT |
| `keep_alive_interval` | integer | `null` | keepalive 间隔 |
| `congestion_controller` | string enum | `null` | 拥塞控制器 |
| `up` | string | `null` | 上行速率表达式 |
| `down` | string | `null` | 下行速率表达式 |
| `cwnd` | integer | `null` | 拥塞窗口 |
| `bbr_profile` | string enum | `null` | BBR profile |
| `recv_window_conn` | integer | `null` | 单连接接收窗口 |
| `recv_window` | integer | `null` | 全局接收窗口 |
| `disable_mtu_discovery` | boolean | `false` | 禁用 MTU discovery |
| `max_datagram_frame_size` | integer | `null` | 最大 datagram frame size |
| `max_open_streams` | integer | `null` | 最大打开流数 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`username`。

### 6.15 `shadowsocks`

<!-- subio-example:shadowsocks -->
```toml
version = 1

[[nodes]]
name = "SS-v2ray-plugin"
type = "shadowsocks"
server = "ss.example.com"
port = 8388
cipher = "aes-256-gcm"
password = "secret"
plugin = "v2ray-plugin"

[nodes.plugin_opts]
mode = "websocket"
host = "cdn.example.com"
path = "/proxy"
tls = true
skip_cert_verify = false
headers = { User-Agent = "SubIO" }
```
<!-- /subio-example -->

`cipher = "none"` 时密码可以为空；其他 cipher 必须提供密码。插件的允许字段见 4.6，目标是否支持
对应 cipher/plugin 由 capability 检查。

<!-- protocol-fields:shadowsocks -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `cipher` | string | `chacha20-ietf-poly1305` | cipher 名；必须被目标支持 |
| `password` | string | 空字符串 | 除 `cipher = "none"` 外必填 |
| `udp_port` | integer | `null` | 独立 UDP 端口 |
| `plugin` | string enum | `null` | 见 4.6 的七种 plugin |
| `plugin_opts` | object | `null` | 严格 plugin 参数对象 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`cipher`、`password`、`port`、`server`。

### 6.16 `shadowsocksr`

<!-- subio-example:shadowsocksr -->
```toml
version = 1

[[nodes]]
name = "SSR"
type = "shadowsocksr"
server = "ssr.example.com"
port = 8388
cipher = "aes-256-cfb"
password = "secret"
obfs = "tls1.2_ticket_auth"
ssr_protocol = "auth_aes128_sha1"
obfs_param = "cdn.example.com"
protocol_param = "1000:user"
```
<!-- /subio-example -->

<!-- protocol-fields:shadowsocksr -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `cipher` | string | 空字符串（校验失败） | 必填 SSR cipher |
| `password` | string | 空字符串（校验失败） | 必填密码 |
| `obfs` | string | 空字符串 | SSR obfs 名称 |
| `ssr_protocol` | string | 空字符串 | SSR protocol 名称 |
| `obfs_param` | string | `null` | obfs 参数 |
| `protocol_param` | string | `null` | protocol 参数 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`cipher`、`password`、`port`、`server`。

### 6.17 `snell`

<!-- subio-example:snell -->
```toml
version = 1

[[nodes]]
name = "Snell"
type = "snell"
server = "snell.example.com"
port = 443
psk = "secret"
version = 5
reuse = true

[nodes.obfs_opts]
mode = "shadow-tls"
host = "cdn.example.com"
password = "shadow-secret"
version = 3
```
<!-- /subio-example -->

Snell version 接受 `1..6`；平台支持范围不同。`udp_port` 仅适用于 v3 及以上且当前主要由 Surge 表达；
`mode` 只用于 v6。`obfs_opts` 的严格字段见 4.6；简单模式也可以只写 `obfs` 与 `obfs_host`。

<!-- protocol-fields:snell -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `psk` | string | 空字符串（校验失败） | 必填预共享密钥 |
| `version` | integer enum | `null`（按 v1 处理） | `1` 到 `6` |
| `reuse` | boolean | `null` | 连接复用开关；只在部分版本生效 |
| `udp_port` | integer | `null` | 独立 UDP 端口 |
| `mode` | string | `null` | Snell v6 mode |
| `obfs` | string | `null` | 简单 obfs mode |
| `obfs_host` | string | `null` | 简单 obfs host |
| `obfs_opts` | object | `null` | 严格 obfs 对象 |
| `tls` | object | 禁用 | 解析/目标共享的 TLS 设置 |
| `smux` | object | 禁用 | sing-mux 设置 |
<!-- /protocol-fields -->

可按用户覆盖：`port`、`psk`、`server`。

### 6.18 `socks5`

<!-- subio-example:socks5 -->
```toml
version = 1

[[nodes]]
name = "SOCKS5"
type = "socks5"
server = "socks.example.com"
port = 1080
username = "alice"
password = "secret"
```
<!-- /subio-example -->

用户名和密码都省略时表示无认证。

<!-- protocol-fields:socks5 -->
| 字段 | 类型 | 省略时 | 说明 |
|---|---|---|---|
| `username` | string | `null` | SOCKS5 用户名 |
| `password` | string | `null` | SOCKS5 密码 |
| `tls` | object | 禁用 | TLS-wrapped SOCKS 设置，目标支持范围不同 |
<!-- /protocol-fields -->

可按用户覆盖：`password`、`port`、`server`、`username`。
