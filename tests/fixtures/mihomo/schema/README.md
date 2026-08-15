# Mihomo schema fixture

- Source: <https://github.com/dongchengjie/meta-json-schema>
- Commit: `88d5239f9b5db8340bcdda3c963fe7fc5f6f5dbb`
- Schema entry: `src/modules/config/proxies.json`
- Extracted: 2026-08-16

`proxies-88d5239.json` is the offline review snapshot used by normal tests. Tests must
not require the untracked `vendor/meta-json-schema/` checkout. To refresh it, check
out the recorded schema commit, compare the proxy `const` values and the selected
outbound property names, then update the fixture and this provenance record together.

The TLS labels intentionally preserve the schema distinction between `fingerprint`
(server certificate SHA-256) and `client-fingerprint` (TLS client fingerprint).
