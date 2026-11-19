# SubIO v2

把本地节点和远程订阅整理成 Mihomo、Surge、sing-box 等客户端可用的配置。同一份来源可以筛选、改名，
也可以与其他来源合并，再一次生成多个客户端的配置。

SubIO 转换代理节点和可独立分享的规则集。DNS、策略组等客户端设置由各目标的模板定义；导入一份客户端配置时，
SubIO 只提取它支持的节点。

[快速开始](#快速开始) · [支持的格式](#支持的格式) · [常用订阅配方](docs/recipes.md) · [HTTP 订阅部署](docs/get_rendering.md)

## 安装

需要 Python 3.11 或更高版本。从 GitHub 安装命令行工具：

```bash
uv tool install git+https://github.com/EkkoG/subio.git
```

使用 pip 时，在已激活的虚拟环境中运行
`python -m pip install "subio @ git+https://github.com/EkkoG/subio.git"`。

## 快速开始

先用示例节点为 Mihomo 和 Surge 各生成一份配置：

```bash
subio init my-subio --target mihomo --target surge
cd my-subio
subio convert --dry-run
```

生成的文件是 `dist/mihomo.yaml` 和 `dist/surge.conf`。`--dry-run` 会在当前目录写出文件，
但不会上传；如果配置了远程来源，仍会读取订阅。只想验证配置时，运行 `subio check`，它会检查输入、
转换和模板，但不写产物。

示例节点只用于验证流程。要实际连接，在 `provider/nodes.toml` 中填入自己的节点信息。已有 Mihomo
订阅地址时，可以改用它：把 `config.toml` 中原来的 `[[provider]]` 整段替换为下面的内容，并换成你的 URL。

```toml
[[provider]]
name = "entry"
type = "mihomo"
url = "https://subscription.example.com/nodes"
```

`name` 保留为 `entry`，这样两个输出都能找到这个来源。`type` 填**原订阅的格式**；输出格式由
`[[artifact]]` 各自的 `type` 决定。修改后重新运行 `subio convert --dry-run`，把 `dist/` 中
对应的文件导入客户端。策略组、端口等设置可在 `template/` 中编辑。

## 支持的格式

| 用途 | 格式 |
| --- | --- |
| 节点输入 | Mihomo、Stash、Surge、sing-box、v2rayN 分享链接或订阅、[SubIO v2 节点文件](docs/subio_node_format.md) |
| 节点输出 | Mihomo、Stash、Surge、sing-box、dae、v2rayN |
| 可分享规则集输入 | Mihomo / Stash 的 text、YAML、MRS；Surge 的 Rule Set 和 Domain Set；sing-box 的 Source JSON |

这里列的是格式，具体协议和字段要看[支持矩阵](docs/support_matrix.md)。目标无法保留所需的协议参数
或规则语义时，SubIO 会报告问题，默认停止生成。sing-box 输出需要 JSON 模板来组合节点与路由规则。
`clash-meta` 仍是 `mihomo` 的兼容别名；原版 `clash` 已废弃，仍支持其原有格式的输入和输出。

## 接下来可以做什么

| 需求 | 从这里开始 |
| --- | --- |
| 合并多份订阅，筛选、排序或改名 | [多来源配方](docs/recipes.md#多份来源一次生成多种客户端配置) |
| 用一个节点做入口、另一个做落地 | [代理链配方](docs/recipes.md#机场入口加落地节点) |
| 给客户端提供可刷新的订阅 URL | [启动 HTTP 渲染服务](docs/get_rendering.md)，再用 [`subio links`](docs/recipes.md#生成订阅链接与本地二维码) 生成链接、受支持的客户端导入 URI 或本地二维码 |
| 在模板中使用规则集，或配置 Age 和 GitHub Gist | [可运行的示例与配置参考](example/README.md)、[发布与加密配方](docs/recipes.md#发布与加密) |
| 排查哪些来源或输出有问题 | `subio inspect providers`、`subio inspect artifacts` |

## 从源码运行

```bash
git clone https://github.com/EkkoG/subio.git
cd subio
uv sync
uv run subio convert example/config.toml --dry-run
```

示例只读仓库内的样例数据，不需要真实订阅。直接在源码仓库使用 CLI 时，在命令前加 `uv run`。
更多内容见[文档索引](docs/README.md)和[开发指南](docs/DEV.md)。

项目灵感来自 [Surgio](https://surgio.js.org/)。
