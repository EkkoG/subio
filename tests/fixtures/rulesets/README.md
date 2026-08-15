# Shareable ruleset fixtures

These files freeze syntax facts for the three supported input dialects. They are
test data, not complete application profiles.

Sources extracted on 2026-08-16:

- Mihomo rules: <https://wiki.metacubex.one/config/rules/>
- Mihomo rule-provider content: <https://wiki.metacubex.one/config/rule-providers/content/>
- Stash rule types: <https://stash.wiki/rules/rule-types>
- Stash rule sets: <https://stash.wiki/rules/rule-set>
- Surge Rule Set: <https://manual.nssurge.com/rules/ruleset.html>
- Surge logical rules: <https://manual.nssurge.com/rules/logical.html>
- Surge script rules: <https://manual.nssurge.com/rules/script.html>

Supported source combinations recorded here:

| Dialect | Behavior | Format |
| --- | --- | --- |
| Mihomo | domain, ipcidr, classical | yaml, text |
| Stash | domain, ipcidr, classical | yaml, text |
| Surge | classical Rule Set, domain Domain Set | text |

Mihomo and Stash additionally support MRS only for domain and ipcidr. `SCRIPT`
fixtures carry an external dependency on a complete profile and must never be
executed by SubIO. Surge `FINAL` and `pre-matching` are saved as invalid Rule Set
inputs so later codecs can reject them explicitly.
