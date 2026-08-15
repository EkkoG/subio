# Repository Guidelines

- 只维护 SubIO v2；协议或平台改动前先读 `docs/DEV.md`。
- 项目只转换节点和规则，不建立完整平台配置 IR。
- Mihomo 字段以 `vendor/meta-json-schema/` 为参考；`vendor/` 不提交。
- 先运行 `uv run subio convert example/config.toml --dry-run`，再跑目标测试和
  `uv run python -m pytest tests/`。
- 保留用户已有改动；不要提交 `dist/`、凭据或无关格式化。
- 一阶段一提交。修复提交写明问题、方案、验证；功能提交写明功能、实现、验证。
- 可用时最多启用 3 个 subagent 做相互独立的只读审查或实现任务。
