SubIO 是一个类似于 [Surgio](https://surgio.js.org/) 的订阅转换工具，但是更加轻量级，更易扩展新协议。

### 原理

SubIO 通过将已知的配置格式转换成一个统一的内部数据结构，然后再根据配置将内部数据结构转换成目标格式。

SubIO 和 Surgio 一样，主要有两部分组成，一部分是解析器，负责解析订阅中的节点并转换成内部数据结构，另一部分是渲染器，负责将内部数据结构转换成目标格式。

使用 SubIO 至少需要定义一个输入（provider）、一个转换规则（模板）和一个输出（artifact）。

### 安装

#### 使用 pip 安装

```shell
pip3 install -e git+https://github.com/ekkog/subio#egg=subio
```

安装后使用 `subio2` 命令运行。

#### 从源码安装（使用 uv）

```shell
# 克隆仓库
git clone https://github.com/ekkog/subio.git
cd subio

# 安装 uv（如果尚未安装）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 安装依赖并创建虚拟环境
uv sync

# 运行 subio2
uv run subio2
```

### 使用

- 在当前目录下，创建配置文件 `config.toml`，内容参考 [config.toml](./example/config.toml)。SubIO 也支持 yaml/json/json5 格式的配置
- 在当前目录下新建 `template` 目录，并在该目录下创建模板文件，参考 [template](./example/template/clash.yaml)。
- 可以在当前目录下创建 `snippet` 目录，用于存放一些公共的配置片段，参考 [snippet](./example/snippet)。 snippet 语法参考 [Jinja2](https://jinja.palletsprojects.com/en/3.0.x/templates/#macros)。
- 可以在模板中引用远程规则集，规则集需要在配置文件中定义

然后执行 `subio2` 命令即可。

```shell
# 使用默认配置文件（自动查找 config.toml/yaml/yml/json/json5）
subio2

# 指定配置文件
subio2 example/config.toml

# 干运行模式（不推送到远程，仅本地生成）
subio2 example/config.toml --dry-run

# 清理 gist 中所有现有文件后再上传
subio2 example/config.toml --clean-gist
```

### 致谢

- [Surgio](https://surgio.js.org/)
