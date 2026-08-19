# Runnable examples

`config.toml` is the default end-to-end example. It is intentionally offline:

- every provider reads a local synthetic fixture;
- conversion errors remain fail-closed;
- artifacts cover Mihomo, Stash, Surge, dae, v2rayN, raw emitter output,
  provider filtering, rename, dialer chains, JSON5, and multi-user overrides;
- `snippet/workflow_rules` demonstrates logical rules, process matching, port
  lowering, and `MATCH`/`FINAL` lowering.

Run it from the repository root:

```bash
uv run subio convert example/config.toml --dry-run
```

`config.remote.toml` documents remote Mihomo and Surge providers, explicit and
default ruleset codecs, User-Agent, multiple uploads, and Age configuration.
The end-to-end suite exercises the same functions with a temporary local HTTP
server and an ephemeral Age keypair, so no public service or committed private
key is required.

The new provider fixtures and `workflow_rules` use reserved `.example.test`
hostnames, documentation IP ranges, and conspicuous example credentials. They
are test data, not usable endpoints.
