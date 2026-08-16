# SubIO 节点文件格式 v1

SubIO 节点格式是一种平台无关的代理节点描述格式。

它只描述代理节点，不包含代理组、DNS 配置、脚本、规则、模板或其他完整配置内容。SubIO 节点格式
不是 Mihomo YAML 的别名；节点类型和字段名称以 SubIO 的节点语义为准。

机器可读的结构与类型 schema 见 `schemas/subio-node-v1.schema.json`。它用于检查顶层结构、允许字段、
基础 JSON 类型和 enum；协议必填项、字段组合、数值范围和目标兼容性仍由 SubIO runtime 检查。
目标平台支持范围见 `docs/support_matrix.md`。

## 1. Provider 配置

本地文件：

```toml
[[provider]]
name = "self-hosted"
type = "subio"
file = "nodes.toml"
```

远程文件和 age 解密继续使用通用 provider 选项：

```toml
[[provider]]
name = "private-nodes"
type = "subio"
url = "https://example.com/nodes.json"
age = true
```

`filter`、`rename`、`override`、`relation`、`users` 和 artifact 处理方式不因输入改为原生格式而
改变。`subio` 目前只用于 provider 输入；没有 `artifact.type = "subio"`。

## 2. 顶层结构

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

顶层只有两个字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `version` | integer | 必须为 `1` |
| `nodes` | array<object> | 节点列表 |

固定规则：

- TOML、JSON、JSON5、YAML 是同一对象模型的不同序列化；
- `type` 使用规范名称，例如 `shadowsocks`，不接受 Mihomo 的 `ss`；
- 字段使用 snake_case，例如 `skip_cert_verify`，不接受 `skip-cert-verify`；
- 未知顶层字段、节点字段、节点类型和错误字段类型会产生结构化解析错误；
- 可选字段通过省略表达，显式 `null` 不属于 v1；
- 单个节点错误不会丢弃同一文件中其他合法节点；
- `version` 或 `nodes` 已出现时，解析失败不会退回 Mihomo codec。

YAML 中的同一节点写法如下：

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

除不需要远程端点的特殊节点外，大多数协议至少需要 `name`、`type`、`server` 和 `port`。协议自身
的必填条件见第 6 节。

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | string | 节点名称，不能为空 |
| `type` | string | 第 6 节列出的规范协议名称 |
| `server` | string 或 string[] | 远程地址；是否允许数组及目标输出方式由协议和目标决定 |
| `port` | integer | 远程端口；需要端点时必须为 1～65535 |
| `udp` | boolean | 是否请求 UDP 能力；目标仍会按协议检查 |
| `ip_version` | string | IP 选择语义，例如 `ipv4`、`ipv6` 或 `dual` |
| `tfo` | boolean | TCP Fast Open |
| `mptcp` | boolean | Multipath TCP |
| `dialer_proxy` | string | 底层代理节点名称 |
| `interface_name` | string | 出站接口名称 |
| `routing_mark` | integer | 路由标记；当前主要由 Mihomo-family 输出 |
| `users` | object | 按 artifact 用户应用的端点或凭据覆盖，见第 5 节 |
| `tls` | object | 协议公开 TLS 时可用，见第 4 节 |
| `transport` | object | 协议公开传输层时可用，见第 4 节 |
| `smux` | object | 协议公开复用设置时可用，见第 4 节 |
| `shadow_tls` | object | 强类型 ShadowTLS 语义，见第 4 节 |
| `surge_options` | object | 强类型 Surge policy 选项，见第 4 节 |

`tls`、`transport` 和 `smux` 并非每个协议都接受。原生 codec 按节点 `type` 使用严格字段白名单，
不能把某协议的字段放到另一个协议中。

以下内部字段永远不能由原生文件注入：`source_context`、`source_provider`、`original_name`、
`extra`、`source_extensions`、`transport.extra` 和 `SourcePassthroughNode`。Surge External 也不属于
原生格式。`SSH.keystore_id`、`tls.client_cert_ref` 和 Tailscale `interactive_login` 引用本机
Surge Keystore 或登录状态，同样只由 Surge parser 的节点附件恢复，不是可分享字段。

## 4. 共享结构

### 4.1 TLS

```toml
[nodes.tls]
enabled = true
server_name = "example.com"
alpn = ["h2", "http/1.1"]
skip_cert_verify = false
client_fingerprint = "chrome"
```

公开字段：

`enabled`、`server_name`、`alpn`、`skip_cert_verify`、`client_fingerprint`、`reality_opts`、
`ech_opts`、`certificate`、`private_key`、`sni_disabled`、`verify_name`、
`certificate_sha256`。

客户端 TLS 指纹、服务端证书 SHA-256、SNI 和证书验证名称是不同语义，不应互相代替。
`reality_opts` 是 string-to-string 对象；`ech_opts` 是受 JSON 值类型限制的对象。

### 4.2 Transport

```toml
[nodes.transport]
network = "ws"
path = "/proxy"
headers = { Host = "example.com" }
max_early_data = 2048
early_data_header_name = "Sec-WebSocket-Protocol"
```

公开字段：`network`、`path`、`headers`、`host`、`method`、`grpc_service_name`、`xhttp_mode`、
`max_early_data`、`early_data_header_name`。

常用 `network` 为 `tcp`、`ws`、`http`、`h2`、`grpc`、`xhttp`。原生格式可以记录已建模的其他
字符串值，但目标 emitter 仍会拒绝无法表达的 transport。平台保真用的 `transport.extra` 不公开。

### 4.3 SMUX

```toml
[nodes.smux]
enabled = true
protocol = "smux"
max_connections = 4
min_streams = 4
max_streams = 0
padding = false
```

公开字段：`enabled`、`protocol`、`max_connections`、`min_streams`、`max_streams`、`padding`、
`brutal_opts`。具体组合和值域由协议与目标检查；不要假设所有目标支持同一种复用实现。

### 4.4 其他共享对象

| 对象 | 公开字段 |
|---|---|
| `shadow_tls` | `password`、`server_name`、`version` |
| `surge_options` | `allow_other_interface`、`dns_follow_interface`、`no_error_alert`、`hybrid`、`tos`、`ecn`、`block_quic`、`test_url`、`test_timeout`、`test_udp` |
| WireGuard `peers[]` | `server`、`port`、`public_key`、`allowed_ips`、`preshared_key`、`reserved` |
| Sudoku `httpmask` | `disable`、`mode`、`tls`、`host`、`path_root`、`multiplex` |

这些字段进入 Node IR 不代表每个目标都能输出。不能表达的平台会生成字段级 issue，而不是静默删除。

## 5. 多用户节点

`users` 将 artifact 用户名映射到该用户的节点覆盖。共享节点不写 `users`；写了 `users` 的节点只会
进入名单中对应用户的 artifact。

```yaml
version: 1
nodes:
  - name: ssh-personal
    type: ssh
    server: ssh.example.com
    port: 22
    username: default
    users:
      alice:
        username: alice
        private_key: alice-private-key
      bob:
        username: bob
        password: bob-password
```

每个用户覆盖应用后必须形成合法节点。上例允许默认节点不带 SSH 认证，因为 `alice` 和 `bob` 的
具体节点都提供了认证；若某个已声明用户缺少认证，错误路径会指向
`nodes[<index>].users.<user>.<field>`。

可覆盖字段只限端点和凭据语义：`server`、`port`、`username`、`password`、`uuid`、`cipher`、
`alter_id`、`token`、`auth`、`auth_str`、`auth_key`、`psk`、`private_key`、
`private_key_passphrase`、`public_key`、`preshared_key`、`obfs_password`。每个协议只能使用其中实际
存在的字段；精确白名单见 JSON Schema。`type`、`tls`、`transport`、`smux`、`users` 等结构字段
不能按用户覆盖。

## 6. 协议字段索引

表中“要求”描述运行时最小语义，不是目标平台支持保证。除明确说明外，需要端点的协议还要求
`server` 和 `port`。

| `type` | 协议字段 | 要求或重要组合 |
|---|---|---|
| `anytls` | `password`、`tls`、`reuse`、`idle_session_check_interval`、`idle_session_timeout`、`min_idle_session` | 端点和 `password` |
| `direct` | `smux` | 不需要端点 |
| `dns` | `smux` | 不需要端点；只表示 Mihomo 内部 DNS 出站，不是 DNS section |
| `gost-relay` | `forward`、`mux`、`username`、`password`、`tls`、`smux` | 需要端点；`mux` 与 `smux` 是不同机制 |
| `http` | `username`、`password`、`headers`、`variant`、`max_streams`、`tls` | 需要端点；`variant` 为 `auto`、`http`、`https` 或 `h2-connect` |
| `hysteria` | `ports`、`hysteria_protocol`、`obfs_protocol`、`up`、`down`、`up_speed`、`down_speed`、`auth_str`、`auth`、`obfs`、`hop_interval`、`tls`、`smux` | 需要端点 |
| `hysteria2` | `password`、`ports`、`hop_interval`、`up`、`down`、`obfs`、`obfs_password`、`tls`、`smux` | 端点和 `password` |
| `juicity` | `uuid`、`password`、`tls` | 端点、`uuid` 和 `password` |
| `masque` | `mode`、`transport`、`connect_uri`、`username`、`password`、`private_key`、`public_key`、`interface_ip`、`interface_ipv6`、`mtu`、`ports`、`hop_interval`、`remote_dns_resolve`、`dns_servers`、`congestion_controller`、`cwnd`、`bbr_profile`、`handshake_timeout`、`tls`、`smux` | `forward-proxy` 可选成对 Basic 认证；`connect-ip`/`h3-l4proxy` 需要密钥，`connect-ip` 还需要隧道地址 |
| `mieru` | `port_range`、`transport`、`username`、`password`、`multiplexing`、`handshake_mode`、`traffic_pattern`、`smux` | `server`、`transport`、`username`、`password`，且 `port`/`port_range` 必须二选一 |
| `openvpn` | `proto`、`dev`、`cipher`、`data_ciphers`、`data_ciphers_fallback`、`auth`、`comp_lzo`、`ca`、`certificate`、`private_key`、`tls_auth`、`key_direction`、`tls_crypt`、`tls_crypt_v2`、`username`、`password`、`peer_info`、`ping`、`ping_restart`、`handshake_timeout`、`mtu`、`remote_dns_resolve`、`dns_servers`、`smux` | 端点和 `ca`；`certificate`/`private_key` 成对，否则需要 `username`；三种 control-channel key 互斥 |
| `reject` | `mode`、`smux` | 不需要端点；`mode` 为 `reject`、`reject-drop`、`reject-no-drop`、`reject-tinygif` |
| `rematch` | `target_rematch_name`、`target_sub_rule`、`smux` | 不需要端点；两个目标字段至少出现一个 |
| `shadowquic` | `username`、`password`、`tls`、`quic_versions`、`udp_over_stream`、`zero_rtt`、`keep_alive_interval`、`congestion_controller`、`up`、`down`、`cwnd`、`bbr_profile`、`recv_window_conn`、`recv_window`、`disable_mtu_discovery`、`max_datagram_frame_size`、`max_open_streams`、`smux` | 需要端点 |
| `shadowsocks` | `cipher`、`password`、`udp_port`、`plugin`、`plugin_opts`、`smux` | 端点、`cipher` 和 `password` |
| `shadowsocksr` | `cipher`、`password`、`obfs`、`ssr_protocol`、`obfs_param`、`protocol_param`、`smux` | 端点、`cipher` 和 `password` |
| `snell` | `psk`、`version`、`reuse`、`udp_port`、`mode`、`obfs`、`obfs_host`、`obfs_opts`、`tls`、`smux` | 端点和 `psk` |
| `socks5` | `username`、`password`、`tls` | 需要端点 |
| `ssh` | `username`、`password`、`private_key`、`private_key_passphrase`、`host_key`、`host_key_algorithms`、`idle_timeout`、`server_fingerprints` | 端点、`username`，以及 `password`/`private_key` 至少一个 |
| `sudoku` | `key`、`aead_method`、`padding_min`、`padding_max`、`table_type`、`enable_pure_downlink`、`multiplex`、`httpmask`、`custom_table`、`custom_tables`、`legacy_http_mask`、`legacy_http_mask_mode`、`legacy_http_mask_tls`、`legacy_http_mask_host`、`legacy_path_root`、`legacy_http_mask_strategy`、`legacy_http_mask_multiplex`、`smux` | 端点和 `key`；`padding_max` 不得小于 `padding_min`；HTTP mask 新旧字段不能冲突 |
| `tailscale` | `hostname`、`auth_key`、`control_url`、`state_dir`、`ephemeral`、`accept_routes`、`exit_node`、`exit_node_auto_fallback`、`exit_node_allow_lan_access`、`derp_only`、`auto_add_magic_dns_rule`、`idle_keepalive`、`prefer_ipv6`、`dns_servers`、`mtu`、`smux` | 不需要传统远程端点；登录、exit-node 和目标平台 profile 分开检查 |
| `trojan` | `password`、`tls`、`transport`、`smux` | 端点和 `password` |
| `trusttunnel` | `username`、`password`、`headers`、`max_streams`、`quic`、`websocket`、`health_check`、`congestion_controller`、`cwnd`、`bbr_profile`、`max_connections`、`min_streams`、`tls`、`smux` | 端点、`username`、`password`；QUIC/WebSocket 互斥；`max_streams` 与 connection/min-streams 组合互斥 |
| `tuic` | `token`、`password`、`uuid`、`version`、`ports`、`hop_interval`、`tls`、`smux` | 需要端点；v4 使用 `token`，v5 使用 `uuid` + `password` |
| `vless` | `uuid`、`flow`、`tls`、`transport`、`smux`、`packet_encoding` | 端点和 `uuid` |
| `vmess` | `uuid`、`alter_id`、`cipher`、`global_padding`、`vmess_aead`、`tls`、`transport`、`smux`、`packet_encoding` | 端点和 `uuid` |
| `wireguard` | `private_key`、`public_key`、`preshared_key`、`interface_ip`、`interface_ipv6`、`allowed_ips`、`reserved`、`mtu`、`workers`、`persistent_keepalive`、`amnezia_wg_option`、`peers`、`remote_dns_resolve`、`dns_servers`、`refresh_server_ip_interval`、`smux` | 端点和 `private_key`；使用单 peer 时需 `public_key`，使用 `peers` 时每项需完整端点、公钥和 allowed IP |

字段的精确 JSON 类型、enum 和每个协议可用的 `users` 覆盖字段以
`schemas/subio-node-v1.schema.json` 为准。该 schema 不单独证明节点语义有效；运行时还会检查
required、范围、字段组合和目标平台 capability。

## 7. 目标平台兼容性

原生格式能解析某个节点，不代表每个 artifact 目标都能生成它。例如：

- `routing_mark` 当前主要是 Mihomo-family 字段；
- `surge_options`、`vmess_aead` 或某些 TLS 选项在其他目标上可能没有等价表示；
- MASQUE、Tailscale、Trust Tunnel 即使协议同名，也可能使用不同 profile、transport 或认证方式；
- 平台不支持的 protocol、transport、plugin、字段或组合会产生结构化 conversion issue。

默认情况下 conversion ERROR 会阻止 artifact 发布；`allow_conversion_errors = true` 会整体放行，
只适合已经审阅的调试配置。完整协议输出范围见 `docs/support_matrix.md`。

## 8. 诊断

SubIO v1 使用以下稳定解析 code：

| code | 含义 |
|---|---|
| `parse.subio.unsupported-version` | `version` 不是当前支持的 `1` |
| `parse.subio.invalid-document` | 顶层类型或字段组合错误 |
| `parse.subio.missing-nodes` | 缺少 `nodes` |
| `parse.subio.invalid-node` | `nodes` 中的条目不是对象 |
| `parse.subio.unknown-type` | 未知、来源绑定或不公开的节点类型 |
| `parse.subio.unknown-field` | 顶层、节点、嵌套对象或 user override 出现未知字段 |
| `parse.subio.invalid-field` | 字段类型、enum 或嵌套值错误 |
| `parse.subio.invalid-combination` | 必填项或字段组合不合法 |
| `parse.subio.legacy-proxies` | 使用旧 `proxies` Mihomo-compatible 语法的迁移 WARNING |

issue 的 `field` 使用 `nodes[2].tls.server_name` 形式。错误消息不会回显密码、私钥、UUID、auth key、
证书或整个节点对象。

## 9. Legacy `proxies` 迁移

旧 SubIO 文件可能是 Mihomo proxy 字典的其他序列化：

```yaml
proxies:
  - name: HK-01
    type: ss
    server: hk.example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
```

这条路径暂时继续支持，并按 Mihomo 字段语义解析，同时产生一次
`parse.subio.legacy-proxies` WARNING。迁移时：

1. 增加 `version: 1`；
2. 将 `proxies` 改为 `nodes`；
3. 将 `ss`、`ssr` 等平台别名改为规范 type；
4. 将连字符字段和平台嵌套块改为本文的 snake_case 语义字段；
5. 用 `subio convert ... --dry-run` 检查 capability issue。

`nodes` 与 `proxies` 不能同时出现。原生节点中也不能逐字段混入 Mihomo alias；兼容只发生在整个
legacy 文档入口。

## 10. 版本规则

schema version 与 SubIO 软件版本分离。v1 可以新增向后兼容的可选协议或字段；改变已有字段类型、
枚举、默认语义，或删除、重命名字段，需要新 schema version。内部 Node IR 可以重构，但 v1 codec
必须保持已经发布的输入语义。
