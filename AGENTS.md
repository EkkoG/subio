示例项目运行方法

```bash
uv run subio2 example/config.toml --dry-run
```

示例项目运行结果在 `./dist` 目录下

先测试 example 目录再更新测试用例

单元测试运行方法

```bash
uv run python -m pytest tests/
```

Clash 协议相关改动请先阅读 `DEV.md`（第 2～5 节）。字段定义可参考 `vendor/meta-json-schema/`（未克隆时见 DEV.md 说明）。Clash 单测：

```bash
uv run python -m pytest tests/test_subio_v2_parser_clash*.py -v
```