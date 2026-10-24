# SIS v3 M0 compatibility and migration notes

## Compatibility matrix

| Surface | v2.4.0 behavior | M0 change | Migration impact |
|---|---|---|---|
| Python package | `sis` v2.4 public modules | Additive `sis.v3` namespace and `SCHEMA_VERSION = 1` | Existing imports and function signatures remain unchanged |
| ToolBridge | Existing read-only tools, including experimental `sis_code_preview` | No new tool is registered in the legacy bridge | Agent behavior remains unchanged unless the v3 module is explicitly called |
| HTTP | Existing routes and keyed operator separation | Central explicit POST handler/access inventory; unknown policy is denied | Keyed reader/admin behavior remains; unkeyed loopback demo remains for compatibility |
| SQLite | Existing v2 tables and audit chains | No v3 tables or migrations | No database conversion or rollback operation is required |
| Source manifest | Exact release inventory | Baseline verification mode can verify a pinned Git tree and label development delta | Do not regenerate the release manifest during development |
| Optional dependencies | No mandatory runtime dependencies; optional extras remain optional | Pin build backend to `setuptools==82.0.1`; no new runtime dependency | Core contract/policy code uses only the standard library |

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

Do not wire Codex SDK events, workspace execution, evaluator receipts, new
SQLite stores, or qualified retrieval into this phase. Each requires its own
milestone, API compatibility review, security tests, and independent evidence.
