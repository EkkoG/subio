# GET 参数化渲染

`subio serve` 提供带 URL token 认证的 `GET /subscription/<file_name>`。请求参数替换本地节点文件中的
标量占位符，再经过现有节点解码、校验、目标编码和可信模板，返回一个完整 artifact。
无需附加请求头、登录或 Cookie。可运行的离线配置见 [example/render](../example/render/README.md)。

## 安装与启动

HTTP 服务使用可选的 Starlette/Uvicorn 依赖；普通 CLI 安装无需它们。从仓库根目录运行：

```bash
uv sync --extra server
export SUBIO_RENDER_TOKEN="$(uv run python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run --extra server subio serve example/render/config.toml
```

已有安装可执行 `pip install 'subio[server]'`，再运行 `subio serve CONFIG`。
服务固定监听 `127.0.0.1`，默认端口 `8000`；可用 `--port 8001` 修改端口，没有对外监听选项。
`SUBIO_RENDER_TOKEN` 必须为 32–128 个 ASCII 字母、数字、`_` 或 `-`，缺少或无效时启动失败。
推荐用 `secrets.token_urlsafe(32)` 生成随机值；长度和字符集检查本身不能证明随机性。

配置和输出文件名在启动时读取成同一快照；更改配置后重启。token 也只在启动时读取，轮换方式是
更换环境变量并重启服务。可信本地 provider 和模板文件仍在渲染时读取，必须由操作者控制。

## 发起请求

在另一个已设置相同 `SUBIO_RENDER_TOKEN` 的终端请求示例路由：

```bash
curl --get 'http://127.0.0.1:8000/subscription/yaml-client.yaml' \
  --data-urlencode "token=${SUBIO_RENDER_TOKEN}" \
  --data-urlencode 'name=example-node' \
  --data-urlencode 'host=proxy.example.test' \
  --data-urlencode 'port=1081' \
  --data-urlencode 'udp=false' \
  --data-urlencode 'username=example-user' \
  --data-urlencode 'password=example + & = % # value' \
  --data-urlencode 'controller_secret=example-only'
```

将路径改为 `/subscription/native-client.yaml` 即使用原生 SubIO v2 TOML 源。示例没有远程输入或 uploader，
返回的主机和凭据都是合成数据。HTTP 不写 `dist`、manifest 或请求报告，不发布或上传结果。

查询按 UTF-8 `application/x-www-form-urlencoded` 规则只解码一次：原始 `+` 表示空格，字面
加号应编码为 `%2B`；`&`、`=`、`#`、`%` 也应编码。优先使用 `--get --data-urlencode`，
避免手工拼接 URL。编码后的 `%252B` 解码后仍是字面 `%2B`。接受的首尾空格和 Unicode 原样保留；
不做 trim，也不执行参数里的 `{{ 7 * 7 }}` 或其他模板文本。

## 文件名和参数声明

订阅路径直接使用原有 `artifact.name`，无需声明路由或额外的 `render` 配置。
需要源文件标量替换时，provider 显式设置 `parameterized = true`。请求参数默认按字符串处理，
无需逐个声明；只在需要整数、布尔值、默认值或约束时，在 `artifact.params` 中补充声明。
完整配置见示例，最小声明如下：

```toml
[[provider]]
name = "dynamic"
type = "mihomo"
file = "nodes.yaml"
parameterized = true

[[artifact]]
name = "client.yaml"
type = "mihomo"
providers = ["dynamic"]
template = "client.yaml"
[artifact.params.host]
default = "proxy.example.test"
[artifact.params.port]
type = "integer"
default = 1080
min = 1
max = 65535
```

该配置对应 `/subscription/client.yaml`。所有已配置的 artifact 都可按文件名访问；没有参数的
artifact 无需声明 `params`。文件名按 URL 路径段编码，并在 UTF-8 解码一次后精确匹配，大小写敏感。
只接受配置中的文件名，不拼接磁盘路径，也不读取已有 `dist` 文件；文件名不能含 `/`、`\` 或为 `.`、`..`。
没有文件名枚举接口。

每个 artifact 拥有自己的参数声明；共享 provider 时，各自的默认值、类型和约束独立生效。
固定 `artifact.user` 沿用原有语义；批量 `users = ["alice", "bob"]` 和 `name = "user-{user}.yaml"`
对应 `/subscription/user-alice.yaml` 与 `/subscription/user-bob.yaml`，每次仅生成对应用户的一份结果。
展开后的文件名必须唯一。查询参数不能覆盖选定用户、目标类型、模板、provider 文件或 URL，
也不能提交节点文档或 Jinja 源码。

旧 `artifact.render` 配置会在启动时被拒绝：将 `render.params` 移至 `artifact.params`，删除
`render.route`，并把订阅 URL 改为 `/subscription/<file_name>`；旧 `/render/...` 地址不再可用。

| 参数声明 | 含义 |
|---|---|
| `type` | 可选，默认 `string`；可指定 `integer` 或 `boolean`，不接受数组、对象或 null |
| `required` | 默认 `false`；为 `true` 时必须由请求提供，不能同时设置 `default` |
| `default` | 可选，必须类型正确且满足本声明的全部约束；请求未提供时使用此值 |
| `choices` | 可选的非空列表；元素必须与声明类型一致，请求值和默认值必须在其中 |
| `min` / `max` | 仅用于整数，闭区间边界；整数查询值使用带可选正负号的十进制文本，不截断小数 |
| `allow_empty` | 仅用于已声明字符串，默认 `false`；未声明字符串允许空值，空值与缺失不同 |

例如 `username` 和 `password` 无需声明：请求提供后就是字符串。`port` 若只有
`type = "integer"` 而没有默认值，请求提供时转为整数；没有提供时不加入 `params`。
provider 或最终模板直接引用缺失参数会返回 HTTP 400，不会静默替换为空字符串；即使最终模板
使用 Jinja `default` 过滤器，直接访问缺失键也会失败。默认值应放在 `artifact.params`。
没有被引用的额外请求参数允许存在；没有被引用、没有默认值的类型声明也不要求请求提供。
显式 `required = true` 可要求请求始终提供该字段。

布尔查询值严格使用小写 `true` 或 `false`。参数名为最多 64 字符的 ASCII 标识符：首字符是
字母或 `_`，其余可含数字。最多补充声明 32 个参数。`token` 是保留的认证字段，不得声明为参数。
若节点本身含 `token` 字段，应使用 `node_token` 并写成 `token: "{{ params.node_token }}"`；
字段仍须满足现有 codec 或同方言保真规则。认证 token 永远不会进入 `params`、节点、模板或上游请求。

请求中非法参数名、重复解码后的名字、缺少必填值或违反约束的值都会被拒绝；`host` 和 `%68ost`
视为同名。原始路径与查询合计最多 8 KiB，最多 33 个查询字段（32 个参数加一个 token），每个
解码后的渲染字符串最多 1024 UTF-8 字节；拒绝控制字符和 Unicode 行/段分隔符。

## 本地源的标量替换

仅支持本地 `file` provider：`mihomo`、兼容别名 `clash-meta`、原版 `clash` 的 YAML，以及
`subio` v2 的 TOML、JSON、JSON5、YAML。远程 URL provider 和其他输入族不能启用参数化；
未启用的普通 provider 保持原有字面数据处理。

```yaml
proxies:
  - name: "edge-{{ params.name }}"
    type: socks5
    server: "{{ params.host }}"
    port: "{{ params.port }}"
    password: "{{ params.password }}"
```

源文件先按原格式解码，然后替换 `proxies` 或原生 `nodes` 子树中的标量值。整个值恰好是
`{{ params.port }}` 时，即使源文件加了引号，替换后仍保留声明的整数类型；布尔值同理。
嵌入文本的 `edge-{{ params.name }}` 只允许字符串参数。用户名、密码只是例子：可以替换名称、
主机、端口、嵌套设置、已有列表的标量元素和静态用户覆盖中的标量，不以凭据字段名建立 allowlist。

只识别带可选空白的 `{{ params.NAME }}`，源 provider 不能使用表达式、过滤器、循环或 include。
替换只作用于原始占位符一次，参数中看似占位符的文字不会再次扫描。容器结构、列表长度和 mapping
键必须保持静态；占位符不得出现在键、原生 `version` 或节点子树外的客户端配置段。缺少请求值和
默认值的参数、格式错误的参数 token、非字符串的嵌入替换都会失败。YAML 非循环 alias 按可见路径独立展开，循环被拒绝；
启用参数化的文档也拒绝 `!!pairs` / `!!omap` 等会解码为 tuple 的结构，不能用它们绕过标量遍历。

替换后仍经过原有 native schema、节点语义、目标 codec 和转换 gate。未知 native 字段不会因替换
而变得合法；未知安全 YAML 字段只按已有同方言规则保真。分享链接中的 URI authority、Surge 标识符
或 dae 引号包装无法忠实表达某个值时，可以安全拒绝并返回 HTTP 422，不承诺所有字符串都可用于所有目标。
静态 CLI 的 `allow_conversion_errors = true` 不能绕过 HTTP 的严格转换 ERROR gate。

## 可信最终模板

HTTP 渲染的模板获得单一、不可变、请求独有的 `params` mapping；参数名不会展开
成模板顶层变量。使用 `params["items"]` 等方括号访问可避开 mapping 方法名冲突，`params["self"]`
也可正常访问。名为 `params` 的规则集 callable 与该命名空间冲突时会被拒绝。

本地 Jinja 模板是可信程序。请求值是数据，不会被当成 Jinja 源码执行；作者仍须为输出语法选择
序列化方法。不要把参数拼进未引用的 YAML/JSON/规则语法、动态 include/extends，或文件/网络调用。
安全示例使用现有节点 emitter 与 JSON/YAML 序列化器：

```jinja
secret: {{ params["controller_secret"] | tojson }}
proxies:
{{ nodes.render() | indent(2, true) }}
proxy-groups:
  - name: Example
    type: select
    proxies:
{{ nodes.names() | to_yaml | indent(6, true) }}
```

`tojson` 是 Jinja 自带过滤器，`to_yaml` 是 SubIO 过滤器。它们不能为任意模板提供所有上下文的
自动转义；例如序列化一个规则字符串并不验证其内部规则 grammar。完整客户端其余字段由模板作者负责。
最终响应会包含目标客户端所需的节点凭据；配置 Age 时返回正常的加密 artifact。

## 静态 CLI 与运行边界

包含参数化源的配置在 `convert`、`check`、`inspect` 入口会于 provider/ruleset I/O 前被拒绝，
即使所有 artifact 参数都有默认值也一样，因为源不能从不同 artifact 中选择全局默认上下文。只引用普通源的
artifact 可以在最终模板使用自身的参数默认值；若其中有缺少运行值的必填参数，生成失败并
阻止发布。没有参数声明的静态模板维持原有上下文；现有静态 CLI 与 `subio2` 别名保持原有行为。

每个请求只准备选中 artifact 及其引用的 providers，已有共享 rulesets 仍是依赖。解析器、节点、
参数和渲染状态不跨请求共享。HTTP 不调用发布/上传/manifest 路径，不创建请求报告，不缓存请求参数
或结果。已有未改变上游响应的可选缓存是独立设施，不接收查询参数。

每进程最多同时运行四个渲染任务，超出立即返回 503，不建立无界等待队列。客户端断开或取消等待后，
已开始的同步工作继续占用名额，直到实际结束。现有上游 fetch timeout/大小检查继续生效；Requests
会先缓冲响应再检查 `max_bytes`，因此这不是全局传输内存上限。四个工作线程也不保证可信模板的严格
执行时限；此服务不适用于不可信模板、恶意本地文件或插件。代理连接、速率和请求头限制由操作者设置。

## 响应与错误

应用响应均带 `Cache-Control: no-store, private`、`X-Content-Type-Options: nosniff` 和
`Referrer-Policy: no-referrer`；成功响应另带无反射文件名的 `Content-Disposition: attachment`。
YAML 目标使用 `application/yaml`，完整 sing-box JSON 使用 `application/json`，文本目标使用
`text/plain; charset=utf-8`，Age 使用 `application/octet-stream`。没有 ETag、Last-Modified、
CORS 或携带查询的重定向。媒体类型、attachment 和 nosniff 共同限制浏览器解释行为。

| 状态 | 固定 JSON `error` | 含义 |
|---|---|---|
| 400 | `invalid_request` | 编码/参数错误，或引用了没有请求值和默认值的参数 |
| 401 | `unauthorized` | token 缺少、空、错误或重复 |
| 404 | `not_found` | 认证后没有对应路由 |
| 405 | `method_not_allowed` | 认证后的已知路由使用非 GET 方法 |
| 413 | `request_too_large` | 原始请求、字段数或字符串超限 |
| 422 | `conversion_rejected` | 节点/目标转换 ERROR，未返回部分成功内容 |
| 500 | `internal_error` | 本地配置、模板或内部故障 |
| 502 | `upstream_error` | 配置的上游加载失败 |
| 503 | `busy` | 四个渲染任务仍在运行 |

错误体仅含固定安全 code，不回显值、原始异常或 traceback。原始大小、百分号编码和 UTF-8 检查
先执行，可能返回 400/413；之后以常量时间字节比较验证唯一 token，再查路由、参数、名额和加载源。
框架访问日志关闭，workflow 日志在专用服务生命周期内静默，不记录查询或渲染内容。

## URL token 与 TLS 反向代理

一个服务 token 授权访问全部已配置 artifact（包括批量用户展开的文件）和其中的静态材料；
没有按文件或按用户的 ACL、账号或 token 签发接口。节点凭据和文件名不提供额外授权。泄露的 URL bearer token 可重放，直到更换
环境变量并重启服务。

GET 的 token 和其他凭据会出现在 URL，可能进入客户端/浏览器历史、shell 历史、进程参数、代理
访问或错误日志、APM 和无 TLS 的网络流量。应用的 no-store、no-referrer 和日志关闭无法删除
这些副本。避免记录真实 URL；为共享链接设置相同的保密与轮换流程。

跨主机访问应通过操作者控制的 TLS 反向代理，SubIO 仍只监听 loopback。以下 Nginx 片段示意
专用虚拟主机的日志和缓存关闭；域名、证书路径和连接/速率限制需按部署环境设置：

```nginx
server {
    listen 443 ssl;
    server_name render.example.test;
    ssl_certificate /etc/nginx/tls/render.example.test.crt;
    ssl_certificate_key /etc/nginx/tls/render.example.test.key;

    access_log off;
    error_log /dev/null crit;

    location ^~ /subscription/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_cache off;
        proxy_no_cache 1;
        proxy_cache_bypass 1;
    }
    location / { return 404; }
}
```

该配置通过关闭专用主机的 access log、丢弃 error log，避免其记录 query；同时确认外层负载均衡、
WAF、系统日志收集、APM/trace 和托管平台不采集 URL 查询或响应正文，并关闭这些层的缓存。
如需诊断，使用合成凭据和不含 URL/值的状态计数。TLS 保护传输，不会消除客户端历史或 bearer 重放风险。
