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

CLI 与示例端到端测试：

```bash
uv run python -m pytest tests/test_example_e2e.py -v
```

该测试通过已安装的 `subio` console script 运行离线示例，并额外覆盖失败事务、
本地 HTTP provider/ruleset、Gist dry-run 和 Age 加解密闭环。详细约束见
`docs/e2e_testing.md`。

重构期间的端到端与 adapter 契约层：

```bash
uv run python -m pytest -m contract tests/
```

契约测试的范围、support matrix 映射和可随内部 API 改写的结构测试边界见
`docs/contract_test_coverage.md`。`tests/conftest.py` 维护机器可读的 contract module 清单。

SubIO native v2 的 schema/decoder/docs 正向契约和旧 v1/`proxies` 拒绝行为包含在
`pytest -m contract` 中。

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
