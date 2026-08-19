SubIO 是一个类似于 [Surgio](https://surgio.js.org/) 的多平台代理节点与规则集转换工具，
重点是轻量和易于扩展协议，不承担完整客户端配置的无损中转。

### 原理

SubIO 将已知订阅中的代理节点和可分享规则集转换成统一语义，再按目标平台生成配置片段。

核心由输入 parser/codec 和目标 renderer 组成：前者把节点或规则集解析为语义模型，后者按目标
平台生成配置片段；模板和 artifact 负责组合与发布结果。

使用 SubIO 至少需要定义一个输入（provider）、一个转换模板（template）和一个输出（artifact）。

### 安装

#### 使用 pip 安装

```shell
pip3 install -e git+https://github.com/ekkog/subio#egg=subio
```

安装后使用 `subio` 命令运行（`subio2` 为同一入口的别名）。

#### 从源码安装（使用 uv）

```shell
# 克隆仓库
git clone https://github.com/ekkog/subio.git
cd subio

# 安装 uv（如果尚未安装）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 安装依赖并创建虚拟环境
uv sync

# 运行示例项目，不执行远程上传
uv run subio convert example/config.toml --dry-run
```

### 使用

- 在当前目录下创建配置文件 `config.toml`，内容参考 [config.toml](./example/config.toml)。SubIO 也支持 YAML、JSON 和 JSON5 配置。
- 在当前目录下新建 `template` 目录，并在该目录下创建模板文件，参考 [template](./example/template/mihomo.yaml)。
- 可以在当前目录下创建 `snippet` 目录，用于存放参数化规则片段，参考 [pt](./example/snippet/pt)。第一行声明逗号分隔的 policy 参数，后续每行是规则；`{{ rule }}` 只表示已声明的 policy 参数引用，不是通用 Jinja 模板源码。
- 可以在模板中引用远程规则集；远程规则集需要通过 `[[ruleset]]` 在配置文件中定义。

#### 节点输入

节点 provider 目前支持 `mihomo`、`clash`、`stash`、`surge`、`v2rayn` 和 `subio`。现代
Mihomo YAML 应使用 `type = "mihomo"`；`clash-meta` 仍作为完全等价的兼容别名，但配置加载时会
提示替换为 `mihomo`。`clash` 专指原版 Clash YAML，已废弃但仍按原版能力继续支持，配置加载时
会提示迁移到 `mihomo`。

例如读取 Mihomo YAML 节点：

```toml
[[provider]]
name = "mihomo_nodes"
type = "mihomo"
file = "mihomo.yaml"
```

读取 Stash YAML 节点：

```toml
[[provider]]
name = "stash_nodes"
type = "stash"
file = "stash.yaml"
```

读取平台无关的 SubIO 节点文件：

```toml
[[provider]]
name = "self-hosted"
type = "subio"
file = "nodes.toml"
```

`nodes.toml` 使用版本化的原生节点语义，不是 Mihomo 字段的另一种序列化：

```toml
version = 2

[[nodes]]
name = "HK-01"
type = "shadowsocks"
server = "hk.example.com"
port = 8388
cipher = "aes-256-gcm"
password = "secret"
```

原生格式同时支持 TOML、JSON、JSON5、YAML，四种序列化共享同一严格对象模型。完整字段、协议索引、
多用户覆盖和旧格式拒绝行为见 [SubIO 节点文件格式 v2](./docs/subio_node_format.md)。

`artifact.type` 使用同一命名契约：新配置用 `mihomo`，旧 `clash-meta` 配置保持兼容并产生替代
提示，原版 `clash` 继续使用较小的独立能力范围并产生废弃提示。模板名、artifact 文件名和上传
文件名中的 `clash` 只是用户自定义文本，不会自动重命名。

具体目标协议和跨平台限制见 [支持矩阵](./docs/support_matrix.md)。

原生 SubIO v2 可直接构造当前 27 种公开具体 Node IR；固定 schema 基线中的 26 种 Mihomo 节点
类型和 Stash-only Juicity 均有明确模型。真正未知的 YAML type 只允许回到其来源平台，不能进入
原生 SubIO 文件。Surge External 的本地 file provider 默认可输出回 Surge，远程 URL 默认忽略；
确需远程同平台透传时，在对应 Surge provider 上设置 `allow_unsafe_external = true`。External 不会
跨平台转换，也不会由 SubIO 执行。

#### 规则集输入

远程规则集输入使用 `type`、`behavior` 和 `format` 显式选择 codec：

```toml
[[ruleset]]
name = "mihomo_domains"
url = "https://example.com/domains.yaml"
type = "mihomo"
behavior = "domain"
format = "yaml"

[[ruleset]]
name = "surge_rules"
url = "https://example.com/rules.list"
type = "surge"
behavior = "classical"
format = "text"

[[ruleset]]
name = "stash_ip"
url = "https://example.com/ipcidr.mrs"
type = "stash"
behavior = "ipcidr"
format = "mrs"
```

当三个字段都未声明时，精确默认为 `mihomo + classical + text`；不根据 URL、
扩展名或解析失败切换格式。当前文本输入的合法组合为：

- Mihomo / Stash：`domain | ipcidr | classical` 与 `text | yaml`；其中 MRS 只支持
  `domain | ipcidr`；
- Surge：`classical | domain` 与 `text`。

MRS 由进程内 data-only decoder 解析，不调用 Mihomo CLI 或系统 `zstd`。解码器限制压缩输入和
解压输出大小，并校验 MRS 版本、behavior、计数、trie/IP range 结构与尾部数据；
`classical + mrs` 会直接拒绝。

Mihomo/Stash 的 `.` 仅子域语义、Surge Domain Set 的 `.` 包含根域语义会按方言
分别解析。引用外部脚本或其他规则资源的条目不会被执行；被当前目标无法精确表达的
规则会产生结构化 conversion error，并在 artifact 写入或上传前阻断。

classical 输入支持三平台官方自包含 predicate、options 和 `AND`/`OR`/`NOT`。转换会处理
`MATCH`/`FINAL`、`DST-PORT`/`DEST-PORT`、来源 IP、TCP/UDP 网络类型和进程名/路径模式等已确认的
等价语义；Stash `no-track` 与 Surge 专属 options 只输出到各自平台。

已有 `[[ruleset]] name/url`、模板 callable、policy 参数和输出文本格式保持不变。Python API 中
`EmissionResult.emitted_policy_names` 已移除：成功生成的节点名称从 `supported_nodes` 读取，模板
变量从 `extras["template_context"]` 读取。Parser 和 Emitter 的结构化结果只返回节点、内容和问题；
Surge Keystore 及命名 section 作为节点附件随节点流转。

然后执行 `subio` 命令即可。

```shell
# 使用默认配置文件（自动查找 config.toml/yaml/yml/json/json5）
subio convert

# 指定配置文件
subio convert example/config.toml

# 干运行模式（不推送到远程，仅本地生成）
subio convert example/config.toml --dry-run

# 清理 gist 中所有现有文件后再上传
subio convert example/config.toml --clean-gist
```

### 致谢

- [Surgio](https://surgio.js.org/)

### 开发文档

- [开发约束与架构](./docs/DEV.md)
- [SubIO 节点文件格式 v2](./docs/subio_node_format.md)
- [支持矩阵](./docs/support_matrix.md)
- [端到端测试](./docs/e2e_testing.md)
- [文档索引](./docs/README.md)
- [已完成的项目级计划](./docs/development_plan.md)
