# Future plans

Here we list features we want in the future.

Not in SPEC because too vaguely worded.

- Git push file-level restriction
  - Restrict which files/paths a push is allowed to modify (e.g. deny changes to `.github/`, `Makefile`, etc.)
  - Requires deep pack inspection: the proxy must know the old tree (on the server) and the new tree (in the push) to compute the diff
  - The pack data alone is insufficient — delta-encoded objects reference base objects the proxy doesn't have
  - Likely approach: proxy maintains a local clone, applies the incoming pack, runs `git diff` to identify changed files, allows/blocks, then forwards
  - Heavy feature: disk I/O, extra network round-trips, git subprocess management — should be gated behind explicit config
  - Build separately from branch-level git rules (which are lightweight pkt-line inspection)

- ~~Credential masking~~ → Implemented as "Credential Injection" in SPEC.md
