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

`config.singbox-nodes.toml` demonstrates sing-box node input and full sing-box
client JSON output from one Jinja JSON template. The template combines
`nodes.outbounds()` and `nodes.endpoints()` with rules converted from the local
`singbox_rules` snippet. It also exercises global/provider filters, named
selectors, the `nodes.*` template API, and the legacy plus composable
`filter.*` helpers. Run it from the repository root:

```bash
uv run subio convert example/config.singbox-nodes.toml --dry-run
```

The provider fixtures and `workflow_rules` / `singbox_rules` use reserved
`.example.test` hostnames, documentation IP ranges, and conspicuous example
credentials. They are test data, not usable endpoints.
