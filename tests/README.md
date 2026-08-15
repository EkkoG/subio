# SubIO 测试文档

本目录包含 SubIO（`src/subio_v2`）的测试用例。

## 测试文件

| 模式 | 说明 |
|------|------|
| `test_subio_v2_parser_*.py` | 各格式 Parser |
| `test_subio_v2_emitter_*.py` | 各平台 Emitter |
| `test_subio_v2_workflow_*.py` | WorkflowEngine、上传、拉取 |
| `test_subio_v2_template_*.py` | 模板与 ruleset |
| `test_filters.py` / `test_ruleset.py` | 过滤器与规则集 |

全量 Clash 协议覆盖见 `test_subio_v2_parser_clash_all_protocols.py`。

## 运行测试

首次安装或依赖变化后执行：

```bash
uv sync --dev
```

每次改动先运行示例，再运行目标测试和全量测试：

```bash
uv run subio convert example/config.toml --dry-run
uv run python -m pytest <目标测试> -v
uv run python -m pytest tests/
```

Clash 相关目标测试：

```bash
uv run python -m pytest tests/test_subio_v2_parser_clash*.py -v
```

规则集相关目标测试：

```bash
uv run python -m pytest tests/test_ruleset.py tests/test_subio_v2_template_ruleset*.py -v
```

覆盖率（包名 `subio_v2`）：

```bash
uv run pytest tests/ --cov=subio_v2 --cov-report=term-missing
```

## 生成结果

```bash
uv run subio convert example/config.toml --dry-run
ls dist/
```

开发约定见仓库根目录 `AGENTS.md` 和 `docs/DEV.md`。
