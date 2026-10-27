# Offline GET render example

Run from the repository root. The two routes load separate local sources:
`/render/mihomo` reads Mihomo YAML, and `/render/native` reads native SubIO v2
TOML. Both return one Mihomo client configuration. No uploader or remote input
is configured, and the service does not write `dist` or a manifest.

```bash
uv sync --extra server
export SUBIO_RENDER_TOKEN="$(uv run python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run --extra server subio serve example/render/config.toml
```

In another terminal with the same `SUBIO_RENDER_TOKEN` environment value:

```bash
curl --get 'http://127.0.0.1:8000/render/mihomo' \
  --data-urlencode "token=${SUBIO_RENDER_TOKEN}" \
  --data-urlencode 'name=local-example' \
  --data-urlencode 'host=proxy.example.test' \
  --data-urlencode 'port=1081' \
  --data-urlencode 'udp=false' \
  --data-urlencode 'username=example-user' \
  --data-urlencode 'password=example + & = % # value' \
  --data-urlencode 'controller_secret=example-only'

curl --get 'http://127.0.0.1:8000/render/native' \
  --data-urlencode "token=${SUBIO_RENDER_TOKEN}" \
  --data-urlencode 'username=example-user' \
  --data-urlencode 'password=example-only'
```

These are synthetic credentials and a reserved hostname, not a usable proxy.
The second request demonstrates defaults; username and password remain required.
The quoted port and UDP placeholders become an integer and a boolean after
document decoding. Names demonstrate embedded string interpolation.

`client.yaml` uses `nodes.render()` for nodes, `tojson` for the arbitrary final
template value `controller_secret`, and `to_yaml` for node names. The controller
is not enabled by this example; its optional client `secret` is separate from
the service's reserved `token`. The service token never enters the template.

`convert`, `check` and `inspect` intentionally reject this parameterized-source
configuration before provider/ruleset I/O. Use the HTTP routes to bind it. The
original `example/config.toml` remains the static CLI example.

GET URLs can expose credentials through history, process arguments, network or
proxy logs; `no-store` cannot erase those copies. Read the [operating and
security guide](../../docs/get_rendering.md) before using real credentials or a
TLS reverse proxy.

The offline HTTP integration test loads these shipped files, renders both
routes with URL-encoded synthetic values and checks types, literal data,
isolation and absence of publication:

```bash
uv run --extra server python -m pytest tests/test_example_render_e2e.py -v
```
