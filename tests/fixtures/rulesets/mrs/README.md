# MRS fixtures

These binary fixtures are generated with the official Mihomo release binary:

- Release: `v1.19.29`
- Binary: `mihomo-darwin-arm64-v1.19.29.gz`
- Binary SHA-256: `4dc25df9e899f14161911302a8ee5fc9e202ed9c976fc405bf82c50ff27466ca`
- Version output: `Mihomo Meta v1.19.29 darwin arm64 with go1.26.5 Sat Jul 18 12:19:57 UTC 2026`

Generation commands, run from the repository root:

```bash
mihomo convert-ruleset domain text tests/fixtures/rulesets/mrs/domain-text.list tests/fixtures/rulesets/mrs/domain.mrs
mihomo convert-ruleset ipcidr text tests/fixtures/rulesets/mrs/ipcidr-text.list tests/fixtures/rulesets/mrs/ipcidr.mrs
```

Generated fixture SHA-256 hashes:

- `domain.mrs`: `3e419a319d8005d602a00291af9cbd1741867a8ee8f7f0388054a48dd49e4f0a`
- `ipcidr.mrs`: `2e2d3681c35d0fc747cc73a67b0ba90d2a2d116e5f9759410229b7b140881164`

The hashes are asserted by `tests/test_subio_v2_stage0_fixtures.py`.
MRS currently has no classical behavior; SubIO runtime must eventually decode these
files internally and must not invoke Mihomo.
