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
- 在当前目录下新建 `template` 目录，并在该目录下创建模板文件，参考 [template](./example/template/clash.yaml)。
- 可以在当前目录下创建 `snippet` 目录，用于存放参数化规则片段，参考 [pt](./example/snippet/pt)。第一行声明逗号分隔的 policy 参数，后续每行是规则；`{{ rule }}` 只表示已声明的 policy 参数引用，不是通用 Jinja 模板源码。
- 可以在模板中引用远程规则集；远程规则集需要通过 `[[ruleset]]` 在配置文件中定义。

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
- [当前开发计划](./docs/development_plan.md)
- [文档索引](./docs/README.md)
