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
服务默认监听 `127.0.0.1:8000`。`--host` 可指定绑定地址，`--port` 可修改端口；例如监听全部 IPv4
网卡可用 `--host 0.0.0.0 --port 8000`，IPv6 可用 `--host ::`，也可指定具体网卡地址。

```bash
uv run --extra server subio serve example/render/config.toml --host 0.0.0.0 --port 8000
```

启动时会显示 `Preparing subscription resources...`，随后报告更新和已就绪快照数量、准备耗时及刷新
间隔。看到 `Ready to accept GET requests at http://...` 表示资源预热已完成且端口已实际绑定，可以发起
请求。部分资源失败时显示警告和安全的阶段类别，仍可请求已就绪的输出；刷新失败时会再次显示警告。
日志中的 `0.0.0.0` 或 `[::]` 表示监听所有对应网卡，其他机器应使用服务所在机器的实际地址访问。

`SUBIO_RENDER_TOKEN` 必须为 32–128 个 ASCII 字母、数字、`_` 或 `-`，缺少或无效时启动失败。
推荐用 `secrets.token_urlsafe(32)` 生成随机值；长度和字符集检查本身不能证明随机性。

`SUBIO_RENDER_TOKEN` 通过环境变量读取，不要写入 `config.toml` 或其他配置文件。
从另一个配置项目运行时，`uv --project ../subio run subio serve` 默认读取当前目录的 `config.*`；
`--project` 用于选择 Python 项目环境。配置语法错误会报告行列位置（解析器支持时），
不会回显原始配置、解析异常或 token。
端口占用等 Uvicorn 启动失败会返回非零退出码和固定提示；可用 `--port 8001` 选择其他端口。

配置和输出文件名在启动时读取成同一快照；更改配置后重启。token 也只在启动时读取，轮换方式是
更换环境变量并重启服务。本地 provider、snippet 和模板由操作者控制，在启动准备和后续刷新时读取；
文件修改在成功刷新后可见。

## 资源刷新与可用性

服务启动时预先获取并准备资源，GET 使用每个 artifact 的内存快照。普通 warm 请求不下载源、不读取
provider/snippet/template 文件、不重新解密或解码源序列化，也不重新解析静态节点和规则集。
参数化源保存未绑定文档，每次请求仍需绑定参数、解析节点并经过原有目标校验、模板和可选 Age 加密。
渲染结果、请求参数和目标编码结果不进入共享快照。

| 选项 | 默认值 | 约束 |
|---|---|---|
| `--refresh-interval SECONDS` | 300 秒 | 正整数；每轮准备完成后等待这么久再刷新 |
| `--max-snapshot-age SECONDS` | 900 秒 | 正整数，至少等于 refresh interval |

例如每 60 秒刷新、最多保留 180 秒的资源：

```bash
uv run --extra server subio serve example/render/config.toml \
  --refresh-interval 60 --max-snapshot-age 180
```

只有一个刷新 worker，轮次不会重叠或积压，且独立于四个渲染 worker。资源年龄使用 monotonic 时间，
从该 artifact 最近一次成功准备的轮次开始时计量，慢速获取也计入年龄。刷新在后台构造完整候选，
成功后按 artifact 替换；一次 GET 始终使用同一版本的节点、规则和模板。文件的多次读取不是文件系统
事务，修改多个相互依赖文件时需由操作者协调。

至少一个输出准备成功就会启动，其他尚无快照的已配置路由返回 `503 not_ready`；全部输出均无法准备时，
启动失败并给出不含路径或源正文的提示。独立 provider 或根模板故障只影响依赖它的 artifact；全部
配置的 rulesets 和本地 snippets 仍为共享依赖。准备成功不保证任意请求参数或模板分支都能成功渲染。

获取、空正文、解密、UTF-8 或源序列化解码等异常不发布候选，也不更新旧快照年龄；尚未过期的旧版本
可继续服务，达到 max age 的新请求返回 `503 snapshot_expired`。已有请求可完成；后续成功刷新后自动恢复。
静态解析器正常返回的 `ParseResult` 即使含 ERROR 或无节点的 `fatal_result`，也代表成功获取：
它替换旧内容并更新年龄，由原有 conversion gate 返回 `422 conversion_rejected`。重复成功获取
无效内容保持 422；如果之后获取失败，年龄不再更新，过期后返回 503。

serve 以资源快照为唯一服务缓存，每轮仍有内存去重，远程磁盘响应缓存和 stale fallback 始终关闭。
配置中的 `remote.cache` 仍控制静态 `convert/check/inspect` 的原有策略，不控制 serve，也不会删除
已有磁盘缓存。配置、路由和 token 变化须重启；本地源、snippet 和模板变化等待成功刷新，无需重启。

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

订阅路径直接使用 `artifact.name`，无需声明路由。
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

| 参数声明 | 含义 |
|---|---|
| `type` | 可选，默认 `string`；可指定 `integer` 或 `boolean`，不接受数组、对象或 null |
| `default` | 可选，必须类型正确且满足本声明的全部约束；请求未提供时使用此值 |
| `choices` | 可选的非空列表；元素必须与声明类型一致，请求值和默认值必须在其中 |
| `min` / `max` | 仅用于整数，闭区间边界；整数查询值使用带可选正负号的十进制文本，不截断小数 |

例如 `username` 和 `password` 无需声明：请求提供后就是字符串。`port` 若只有
`type = "integer"` 而没有默认值，请求提供时转为整数；没有提供时不加入 `params`。
provider 或最终模板直接引用缺失参数会返回 HTTP 400，不会静默替换为空字符串；即使最终模板
使用 Jinja `default` 过滤器，直接访问缺失键也会失败。默认值应放在 `artifact.params`。
没有被引用的额外请求参数允许存在；没有被引用、没有默认值的类型声明也不要求请求提供。
字符串统一允许空值，空值与缺失不同；如需限制取值，可使用 `choices`。

布尔查询值严格使用小写 `true` 或 `false`。参数名为最多 64 字符的 ASCII 标识符：首字符是
字母或 `_`，其余可含数字。最多补充声明 32 个参数。`token` 是保留的认证字段，不得声明为参数。
若节点本身含 `token` 字段，应使用 `node_token` 并写成 `token: "{{ params.node_token }}"`；
字段仍须满足现有 codec 或同方言保真规则。认证 token 永远不会进入 `params`、节点、模板或上游请求。

请求中非法参数名、重复解码后的名字或违反约束的值都会被拒绝；`host` 和 `%68ost`
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

服务沿用 `template/` 目录优先、否则配置目录的选择，在每轮准备时捕获有限模板命名空间：现有
Jinja loader 枚举的名称，加上显式配置的根模板。根模板预编译，helper 可在请求中从内存文本编译；
请求 loader 不回退到文件系统。`include`、`extends`、`import`、fallback 列表和 `ignore missing`
在这个命名空间内保留 Jinja 运行语义。枚举不递归目录 symlink，因此仅经目录 symlink 可达且未配置
为根模板的 helper 在 serve 中不可用；请把 helper 放入可枚举的模板目录。显式根模板仍沿用现有
loader 路径解析，静态 CLI 模板行为保持不变。

坏的根模板只阻断其 artifact 候选，未使用的坏 helper 不影响其他 artifact。真正不存在的 helper 可由
`ignore missing` 或 fallback 处理；已发现但无法读取/解码的文件保留失败标记，访问时返回固定 500，
不能被当作不存在而跳过。helper 编译错误也在实际访问时返回 500。helper 删除会在成功刷新后生效，
正在使用旧快照的请求仍可完成。根模板准备成功不检查所有条件分支。

模板始终获得单一、不可变的 `params` mapping；HTTP 中的参数状态属于当前请求。参数名不会展开
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
artifact 可以在最终模板使用自身的参数默认值；若模板引用没有请求值和默认值的参数，生成失败并
阻止发布。没有参数声明时，静态模板的 `params` 是空 mapping。

每轮准备只加载已配置 artifact 引用的 providers；未引用的 provider 不做 I/O，全部配置 rulesets
仍为共享依赖。请求只选择对应 artifact/user，复用其准备资源，并为节点、参数、options、解析器、
emitter 和模板状态创建独立副本或实例。HTTP 不调用发布/上传/manifest 路径，不创建请求报告，
不保存请求参数或结果。请求值不能覆盖配置的源路径、上游请求、根模板、快照版本或刷新调度。
可信模板若使用参数选择 helper，仍只能访问已捕获的模板命名空间。

每进程最多同时运行四个渲染任务，超出立即返回 503，不建立无界等待队列。客户端断开或取消等待后，
已开始的同步工作继续占用名额，直到实际结束。关闭时停止安排刷新和接收新渲染，等待实际刷新及渲染
线程完成，没有硬性关闭期限。旧快照及其源凭据可在已有请求完成前留在内存。现有上游 fetch timeout/
大小检查继续生效，但不是整轮刷新的严格期限；Requests
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
| 502 | `upstream_error` | 渲染时传播的上游异常；后台资源获取失败按快照可用性处理 |
| 503 | `not_ready` | 请求的输出尚无成功准备的资源快照；检查准备日志，修复资源后等待刷新或重启 |
| 503 | `snapshot_expired` | 请求的输出快照已过期；检查刷新失败日志，成功刷新后恢复 |
| 503 | `busy` | 四个渲染任务仍在运行；稍后重试 |

错误体仅含固定安全 code，不回显值、原始异常或 traceback。原始大小、百分号编码和 UTF-8 检查
先执行，可能返回 400/413；之后以常量时间字节比较验证唯一 token，再查路由、参数、快照可用性和渲染名额。
框架访问日志关闭，workflow 日志在专用服务生命周期内静默。独立的服务日志只记录启动、资源准备/
刷新、监听就绪和关闭事件，以及数量、耗时和固定失败阶段，不记录查询、token、源路径或渲染内容。

## URL token 与 TLS 反向代理

一个服务 token 授权访问全部已配置 artifact（包括批量用户展开的文件）和其中的静态材料；
没有按文件或按用户的 ACL、账号或 token 签发接口。节点凭据和文件名不提供额外授权。泄露的 URL bearer token 可重放，直到更换
环境变量并重启服务。

GET 的 token 和其他凭据会出现在 URL，可能进入客户端/浏览器历史、shell 历史、进程参数、代理
访问或错误日志、APM 和无 TLS 的网络流量。应用的 no-store、no-referrer 和日志关闭无法删除
这些副本。避免记录真实 URL；为共享链接设置相同的保密与轮换流程。

外网部署应通过操作者控制的 TLS 反向代理或其他 TLS 入口传输 URL 中的凭据。可保留默认 loopback
监听，也可用 `--host` 绑定代理可达的网卡地址；token 鉴权规则保持不变。以下 Nginx 片段示意
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
