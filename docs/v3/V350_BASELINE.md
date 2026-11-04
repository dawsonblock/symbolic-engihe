# SIS v3.5.0 baseline (PR-00)

This freezes the state the v3.5.0 remediation is measured against and
records what was actually run, not what an archive claims.

## Pinned runtime

`requirements-lock.txt` is the only supported test and production
profile. `tools/check_runtime.py` verifies the interpreter range and
every pin, and exits non-zero on drift.

| Component | Pin |
|---|---|
| Python | 3.12.0 (qualified: >= 3.10, < 4.0) |
| pytest | 8.4.2 |
| psycopg[binary] | 3.3.4 |
| cryptography | 48.0.1 (the only vetted Ed25519 backend) |
| setuptools | 82.0.1 |

`signatures.backend()` reports the active backend. Production refuses
`vendored-python` (`require_vetted_backend`), because that implementation
is wire-compatible but not constant-time.

## Measured baseline

| Run | Result |
|---|---|
| v3.4.0 tree, SQLite profile, pinned runtime | 1296 passed, 12 skipped |
| v3.4.0 tree, PostgreSQL 14.20 profile | 1305 passed, 3 skipped |
| v3.5.0 tree, SQLite profile, pinned runtime | 1346 passed, 12 skipped |
| v3.5.0 tree, PostgreSQL 14.20 profile | 1355 passed, 3 skipped |

The 12 SQLite skips are 9 DSN-gated multi-replica tests plus the three
pre-existing environment skips (Windows ACLs, the skills corpus, the
pinned baseline commit). They are explicit, not silent.

### The audit's 1,249 / 45 / 14

The deep audit ran the archive in a **non-pinned** environment. That
result is not comparable to this table and is not used as an acceptance
number here:

- without `cryptography`, `signatures.backend()` falls back to the
  vendored implementation and any test that pins the vetted backend
  fails;
- a different pytest/Python pair changes collection, warnings-as-errors
  and the `tmp_path` behaviour some fixtures depend on;
- the PostgreSQL profile cannot run at all without a DSN, so those tests
  skip rather than fail.

`tools/check_runtime.py` is the gate that separates the two. A green run
in an unpinned environment is not a release result; neither is a red one.

## Reproductions

`tools/reproduce_v340_defects.py` drives the real production stack and
reports each historical P0 attack as OPEN or CLOSED. On the v3.5.0 tree
all three are CLOSED with stable reasons (`outcome_requester_mismatch`,
`receipt_repository_mismatch`, `receipt_authorization_mismatch`).

## Release manifest

`RELEASE_SHA256.json` inventories every distributed file. Regenerate it
with `tools/build_release.py` and verify with
`tools/verify_release.py .`; `tools/build_release.py --check` fails on a
stale manifest. The manifest is regenerated as the last step of every
commit on this branch.

## What this baseline does not establish

- No efficacy claim. The five-arm campaign has not been run against a
  live agent, and no powered holdout exists in this tree.
- PostgreSQL is qualified locally (14.20, throwaway cluster); a
  deployment must run the profile against its own server.
- Evaluator isolation is still the local subprocess backend. PR-02 in
  the v3.5.0 plan is not implemented on this tree; see
  `V350_IMPLEMENTATION.md`.
