# Surge official proxy fixtures

Sources were reviewed on 2026-08-15:

- https://manual.nssurge.com/policies/overview.html
- https://manual.nssurge.com/policies/parameters.html
- https://manual.nssurge.com/policies/tls.html
- https://manual.nssurge.com/policies/udp.html
- https://manual.nssurge.com/policies/wireguard.html
- https://manual.nssurge.com/policies/tailscale.html
- https://manual.nssurge.com/policies/built-in.html
- https://manual.nssurge.com/policies/masque.html
- https://manual.nssurge.com/policies/trust-tunnel.html
- https://manual.nssurge.com/policies/external.html

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
