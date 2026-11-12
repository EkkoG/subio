# Surge official proxy fixtures

Sources were reviewed on 2026-08-21:

- https://manual.nssurge.com/policies/overview.html
- https://manual.nssurge.com/policies/reject.html
- https://manual.nssurge.com/policies/parameters.html
- https://manual.nssurge.com/policies/tls.html
- https://manual.nssurge.com/policies/udp.html
- https://manual.nssurge.com/policies/wireguard.html
- https://manual.nssurge.com/policies/tailscale.html
- https://manual.nssurge.com/policies/built-in.html
- https://manual.nssurge.com/policies/masque.html
- https://manual.nssurge.com/policies/trust-tunnel.html
- https://manual.nssurge.com/policies/external.html
- https://wiki.metacubex.one/config/proxies/tailscale/
- https://wiki.metacubex.one/config/proxies/masque/
- https://wiki.metacubex.one/config/proxies/trusttunnel/

VLESS sources were reviewed on 2026-11-12:

- https://manual.nssurge.com/policies/vless.html
- https://manual.nssurge.com/policies/tls.html
- https://manual.nssurge.com/policies/udp.html
- https://github.com/XTLS/Xray-core/blob/main/common/uuid/uuid.go

`vless.conf` uses the four official VLESS examples with test endpoints and a
public test identity. VLESS requires Surge iOS 6.0.0 or Mac 6.12.0.

The fixture files contain minimal, non-secret examples distilled from the
official syntax. Tests must not fetch the documentation at runtime.

Update workflow:

1. Extract the current official page with MarkItDown or an equivalent read-only
   web-to-Markdown tool.
2. Distill only the syntax needed for a deterministic regression, replacing all
   real endpoints and credentials.
3. Add the source URL above and update the review date.
4. Update the Surge codec invariants and round-trip/security tests in the same
   change.
