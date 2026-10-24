# SIS v3 M0 compatibility and migration notes

## Compatibility matrix

| Surface | v2.4.0 behavior | M0 change | Migration impact |
|---|---|---|---|
| Python package | `sis` v2.4 public modules | Additive `sis.v3` namespace and `SCHEMA_VERSION = 1` | Existing imports and function signatures remain unchanged |
| ToolBridge | Existing read-only tools, including experimental `sis_code_preview` | No new tool is registered in the legacy bridge | Agent behavior remains unchanged unless the v3 module is explicitly called |
| HTTP | Existing routes and keyed operator separation | Central explicit POST handler/access inventory; unknown policy is denied | Keyed reader/admin behavior remains; unkeyed loopback demo remains for compatibility |
| SQLite | Existing v2 tables and audit chains | No v3 tables or migrations | No database conversion or rollback operation is required |
| Source manifest | Exact release inventory | Baseline verification mode can verify a pinned Git tree and label development delta; in an extracted archive without `.git` the baseline test skips and plain worktree mode correctly fails on unmanifested dev files | Do not regenerate the release manifest during development |
| Optional dependencies | No mandatory runtime dependencies; optional extras remain optional | Pin build backend to `setuptools==82.0.1`; no new runtime dependency | Runner, store, signatures, and verifier are standard-library only; `cryptography` is used in tests only to cross-check Ed25519 |
| Execution | Host subprocesses only via existing demos | `sis.v3.runner` adds disposable workspace execution with `unverified_local` labeling; never presented as a security boundary | Callers must not run hostile code assuming OS isolation; replace backend before multi-tenant use |
| Evidence | v2 SQLite audit | `sis.v3.episode_store` + `sis.v3.verifier` add chained JSONL events, content-addressed artifacts, and Ed25519-signed outcome receipts | No v2 tables changed; v3 stores are separate directories, not SQLite migrations |

## Additive interface rules

V3 records are strict v1 JSON contracts. Unknown fields fail closed. The v3
guidance function currently abstains, and v2 registries are not imported into a
qualified v3 catalog. Legacy local evidence remains local research evidence;
it does not become an independently verified v3 outcome receipt.

No database migration is needed for M0. Future persisted schemas require
additive migration tests and a rollback plan before they can be enabled.

## Source integrity workflow

Run `python tools/check_source_manifest.py` only when the working tree is
expected to match its release manifest. It will correctly fail while the
development tree differs from the baseline manifest. During development or CI,
use `python tools/check_source_manifest.py --baseline-ref <verified-revision>`;
this verifies manifest-listed Git blobs at that revision and reports current
development changes separately. Release packaging may regenerate
`SOURCE_SHA256.json` only after the release inventory is frozen and authorized.

## Later migration gates

Codex SDK events, workspace execution, evaluator receipts, and the episode
store now exist as additive `sis.v3` modules; none of them are wired into the
v2 service, HTTP server, or SQLite schema. Qualified retrieval, promotion, and
any production wiring still require their own milestone, API compatibility
review, security tests, and independent evidence.
