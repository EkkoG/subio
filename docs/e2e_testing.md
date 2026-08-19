# End-to-end testing

The refactor safety net has two layers:

1. `example/config.toml` is a stable, offline happy path that the CLI can run
   without network access or credentials.
2. `tests/test_example_e2e.py` invokes the installed `subio` console script and
   verifies generated artifacts semantically, including failure transactions,
   a local HTTP provider/ruleset, Gist dry-run queueing, and an Age round trip.

The tests deliberately parse generated YAML and Surge content instead of only
checking that files exist. Text formats assert protocol sets, rule lowering,
dialer chains, multi-user isolation, output permissions, and temporary-file
cleanup. A failed artifact must leave pre-existing `dist/` files unchanged.

## Auditing a sensitive legacy project

`scripts/extract_legacy_usage.py` extracts usage structure without serializing
source values. It does not import or execute the scanned project. Source paths,
entity names, comments, URLs, addresses, credentials, and ordinary string
literals are excluded; custom configuration keys and template symbols are
represented by per-run anonymous IDs. Versioned SubIO config keys, CLI words,
node schema fields, and template context/filter API names are retained as
public structural terms.

Use the two-stage flow:

```bash
uv run python scripts/extract_legacy_usage.py extract \
  /path/to/legacy-project /tmp/subio-usage.json \
  --schema schemas/subio-node-v1.schema.json
uv run python scripts/extract_legacy_usage.py gate /tmp/subio-usage.json
uv run python scripts/extract_legacy_usage.py gate /tmp/subio-usage.json --show
```

Only display a report after `gate` succeeds. The gate validates a closed report
schema in which every string is an enum, public structural term, or anonymous
ID; sensitive-pattern checks provide a second boundary. The extractor tests
plant canaries in paths, values, entity names, custom keys, and node records,
reject tampered reports, and refuse symlink output targets.

The report is evidence, not an IR design input. Only node conversion and
officially shareable ruleset scenarios may be transferred into SubIO v2;
policy groups, DNS, MITM, scripts, and complete client configurations stay out
of the shared model.
