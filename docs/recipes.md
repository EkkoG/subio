# 常用订阅配方

## 从可编辑项目开始

在已安装 SubIO 的环境中执行：

```bash
subio init my-subio
subio check my-subio/config.toml
subio convert my-subio/config.toml --dry-run
```

在源码仓库使用时，在命令前加 `uv run`。`init` 默认生成 `basic` 配方和 Mihomo 输出；目标目录
必须不存在或为空，其父目录须已存在。非空目录、文件和目标目录 symlink 均拒绝，不提供覆盖开关。
新建目录权限为 `0700`，文件为 `0600`；已有空根目录保留原权限。写入失败时只清理本次创建的内容。

生成的 `config.toml`、`provider/*.toml` 和 `template/*` 都是普通文件，可直接修改。节点使用
`.test` 示例地址和示例密码；通过检查只证明能转换，实际使用前必须替换为自己的服务器与凭据。
初始化不下载内容、不设置上传，也不生成另一套运行时 preset 配置。

`check` 验证而不写产物；`convert --dry-run` 会写当前工作目录的 `dist/`，只跳过远程上传。

## 多份来源，一次生成多种客户端配置

```bash
subio init my-subio --preset merge --target mihomo --target surge --target sing-box
subio check my-subio/config.toml
```

`merge` 创建两份独立 provider，每个 artifact 都按声明顺序选取两份来源。要替换成远程订阅，
编辑对应 provider，保留 `name`，将 `file` 删除，设置显式输入类型与 `url`，例如：

```toml
[[provider]]
name = "entry"
type = "mihomo"
url = "https://subscription.example.invalid/source"
```

来源格式始终显式选择。相同的节点可以供多个 artifact 使用；各目标不能表示的字段仍会产生 issue，
不会因为选了现成模板就绕过检查。重名默认报错；确需按源顺序保留首个时设置 artifact 的
`on_duplicate_name = "keep_first"`。同名不代表节点内容相同。

## 按名称和协议筛选，再排序

在配置顶层添加：

```toml
[selectors.hk]
name_regex = '香港|Hong Kong|\bHK\b'
exclude_name_regex = '测试|过期'
protocols = ["shadowsocks", "vless"]
sort_by = ["protocol", "name"]
```

在需要的 `[[artifact]]` 内设置 `selector = "hk"`。这是名称匹配，不是 IP 地理位置检测。
`sort_by` 支持 `source_order`、`name`、`protocol`、`source_provider`；`limit` 可限制选中数量。
筛选到零个节点默认失败。代理链不能筛掉已知上游，否则会按已有依赖规则拒绝。

selector 的 `match_original_name = true` 可匹配重命名前的名称。

## 节点重命名

在要改名的 `[[provider]]` 下添加 `[provider.rename]`。替换默认按字面匹配；单条规则设置
`regex = true` 可以用 Python 正则和捕获组，`new = ""` 可删除匹配部分。

```toml
[provider.rename]
add_prefix = "edge-"
replace = [
  { old = '^HK-0*(\d+)-.*$', new = 'HK-\1', regex = true },
  { old = "Hong Kong", new = "HK" },
]
```

替换按声明顺序执行，最后添加前缀和后缀。TOML 单引号会保留正则中的反斜杠。
同一 provider 内的节点引用随改名更新；改名后出现重名时，继续使用 artifact 的重名策略。

## 机场入口加落地节点

```bash
subio init my-chain --preset chain --target mihomo --target surge --target sing-box
subio check my-chain/config.toml
```

将 `provider/nodes.toml` 中的 `entry-ss` 改成入口节点，将 `provider/extra.toml` 中的 `exit-ss`
改成落地节点。配置中的落地 provider 使用 `dialer_proxy = "entry-ss"`：

- Mihomo 输出落地节点的 `dialer-proxy`；
- Surge 输出落地节点的 `underlying-proxy`；
- sing-box 输出落地节点的 `detour`。

Mihomo 和 Surge 客户端中选择 `exit-ss`；初始化的 sing-box 模板默认使用最后一个节点作为
`route.final`。节点名改动后，跨 provider 手写的 `dialer_proxy` 也要指向最终入口名称；同一
provider 内已有节点引用由 rename 自动更新。

## 生成订阅链接与本地二维码

先按 [GET 渲染指南](get_rendering.md) 启动服务。链接工具使用与该服务相同的
`SUBIO_RENDER_TOKEN` 环境变量；它不生成新 token，也不会缩小该 token 的权限。

```bash
subio links my-subio/config.toml --base-url https://subscriptions.example.com
subio links my-subio/config.toml --base-url https://subscriptions.example.com \
  --artifact mihomo.yaml --format json --output subscription-links.json
```

`--artifact` 选择具体输出文件名，包括 `users` 展开的名称，例如 `user-alice.yaml`；不传时列出全部输出。
`--base-url` 可包含反向代理路径前缀，不能包含用户名、密码、query 或 fragment。反代须将该前缀
转发到实际服务。HTTP 可用于本地测试，对外服务应使用 HTTPS。

参数沿用 `convert --param NAME=VALUE` 的字面输入规则；工具负责 URL 编码，例如：

```bash
subio links my-subio/config.toml --base-url https://subscriptions.example.com/subio \
  --artifact mihomo.yaml --param 'label=Hong Kong + Japan' --output links.txt
```

参数类型、约束和请求大小会预检；工具只读配置，不下载 provider、读取模板或执行转换，因此不能证明
源数据已就绪或模板内容有效。有模板且未加密的 Mihomo/Clash、Surge 产物会附带对应配置导入 URI；
模板声明表示完整配置意图，完整性仍由用户负责。无模板节点列表、Age 密文（包括全局加密）和其他
目标仅输出原始 URL，不自动开启客户端。导入方式依据
[Clash Verge 文档](https://www.clashverge.dev/guide/url_schemes.html) 与
[Surge 文档](https://manual.nssurge.com/tools/url-scheme.html)。

源码环境启用二维码可选依赖后，为单个输出生成 SVG：

```bash
uv sync --extra server --extra qr
uv run --extra qr subio links my-subio/config.toml --base-url https://subscriptions.example.com \
  --artifact mihomo.yaml --output links.txt --qr subscription.svg
```

二维码在本机生成，内容是原始订阅 URL，不调用外部二维码服务；URL 超过二维码容量时明确失败，
不截断内容。链接与二维码文件为 `0600`；`--output` 和 `--qr` 会替换各自指定的输出文件。
未指定 `--output` 时会将完整链接写到 stdout。链接和二维码包含 token 与显式参数，持有者获得
相应访问权限；命令行参数也可能进入 shell 历史与进程列表。不要把它们当成不含凭据的普通报告。

## 发布与加密

本地文件生成成功后，普通 `subio convert` 也会按配置上传到 GitHub Gist；先用 `--dry-run`
验证产物。上传者和逐产物上传配置见 [远程示例](../example/config.remote.toml)。需要管理本地旧产物时，
用 `--write-manifest` 记录清单，之后 `--clean-dist` 只删除上一份清单管理的旧文件。

配置 `artifact.age_public_key` 可加密输出。推荐把 Age 私钥保存在仅自己可读的身份文件里，
避免把私钥放进命令行参数。下面第一条 `subio` 命令创建新密钥，第二条显示对应的公钥，
第三条将用该公钥加密的产物解密为本地文件：

```bash
umask 077
subio age keygen > identity.txt
subio age convert --identity-file identity.txt
subio age decrypt --identity-file identity.txt subscription.age subscription.yaml
```

身份文件只包含一个 X25519 identity，可以含空行和以 `#` 开头的注释。解密时省略输出文件会写到
标准输出；输入或输出填 `-` 时分别使用标准输入或标准输出。

## 模板的责任

初始化模板仅提供最小客户端配置。端口、DNS、策略组和其他客户端选项继续由对应模板维护；
SubIO 不导入或转换完整平台配置。sing-box 输出仍必须使用 JSON 模板，通过
`nodes.outbounds()`、`nodes.endpoints()` 组合节点；其他设置由模板负责。

更复杂的规则与节点示例见 [example](../example/README.md)，协议和字段限制见
[支持矩阵](support_matrix.md)，HTTP 订阅部署见 [GET 渲染指南](get_rendering.md)。
