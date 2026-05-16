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

```bash
uv sync --dev
uv run python -m pytest tests/ -v
```

Clash 相关：

```bash
uv run python -m pytest tests/test_subio_v2_parser_clash*.py -v
```

覆盖率（包名 `subio_v2`）：

```bash
uv run pytest tests/ --cov=subio_v2 --cov-report=term-missing
```

## 端到端

```bash
uv run subio example/config.toml --dry-run
ls dist/
```

开发约定见仓库根目录 `AGENTS.md`、`DEV.md`。
