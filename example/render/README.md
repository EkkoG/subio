# Offline GET render example

Run from the repository root. The two routes load separate local sources:
`/subscription/yaml-client.yaml` uses Mihomo YAML, and `/subscription/native-client.yaml` uses native SubIO v2
TOML. Both return one Mihomo client configuration. No uploader or remote input
is configured, and the service does not write `dist` or a manifest.
Paths use the existing artifact output filenames without additional route
declarations. Request parameters default to strings without prior
declarations; `artifact.params` adds types, defaults or constraints where needed.

```bash
uv sync --extra server
export SUBIO_RENDER_TOKEN="$(uv run python -c 'import secrets; print(secrets.token_urlsafe(32))')"
uv run --extra server subio serve example/render/config.toml
```

Startup prepares in-memory resources; later GETs bind parameters and render
from one complete snapshot. Source, snippet and template edits become visible
after a successful background refresh. The default `--refresh-interval 300`
waits 300 seconds after each round completes; `--max-snapshot-age 900` rejects
unready or expired routes with 503. Both options take positive integers and
maximum age must cover the interval. Failed acquisition does not renew age;
successfully acquired conversion errors replace old content and return 422.
Configuration and token changes require a restart. Serve disables remote disk
response caching; `remote.cache` remains the static CLI policy. The detailed
[guide](../../docs/get_rendering.md) covers partial readiness, the finite
template namespace and shutdown behavior.

In another terminal with the same `SUBIO_RENDER_TOKEN` environment value:

```bash
curl --get 'http://127.0.0.1:8000/subscription/yaml-client.yaml' \
  --data-urlencode "token=${SUBIO_RENDER_TOKEN}" \
  --data-urlencode 'name=local-example' \
  --data-urlencode 'host=proxy.example.test' \
  --data-urlencode 'port=1081' \
  --data-urlencode 'udp=false' \
  --data-urlencode 'username=example-user' \
  --data-urlencode 'password=example + & = % # value' \
  --data-urlencode 'controller_secret=example-only'

curl --get 'http://127.0.0.1:8000/subscription/native-client.yaml' \
  --data-urlencode "token=${SUBIO_RENDER_TOKEN}" \
  --data-urlencode 'username=example-user' \
  --data-urlencode 'password=example-only'
```

These are synthetic credentials and a reserved hostname, not a usable proxy.
The second request demonstrates defaults. Username and password have no
declarations; omitting either fails because the provider references it.
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
