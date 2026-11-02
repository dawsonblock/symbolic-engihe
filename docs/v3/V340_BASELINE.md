# SIS v3.4.0 baseline (PR-01)

This document freezes the state the v3.4.0 upgrade is measured against.
Nothing in it is a claim about efficacy; it is the reproducible starting
point for the evidence-chain repairs in PR-02 through PR-05.

## Source baseline

| Item | Value |
|---|---|
| Branch point | `d3dc19e` (`codex/sis-v3.3.1-authority-closure`) |
| Package version | 3.3.2 |
| Working branch | `sis/v3.4.0-engineering-upgrade` |
| `src/sis/v3` size | 50 modules, 17,502 lines |

## Pinned runtime

`requirements-lock.txt` is the only supported test and production
profile. `tools/check_runtime.py` verifies the interpreter range
(>= 3.10, < 4.0) and every pin, and exits non-zero on drift.

| Component | Pin |
|---|---|
| Python | 3.12.0 (qualified: >= 3.10, < 4.0) |
| pytest | 8.4.2 |
| psycopg[binary] | 3.3.4 |
| setuptools | 82.0.1 |

Ed25519 signing runs through `sis.v3.signatures`, which reports its active
backend. A qualification record must state `signatures.backend()`; the
vendored pure-Python fallback is wire-compatible but not constant-time.

## Baseline suite

```
PYTHONPATH=src python3 -m pytest -q
986 passed, 8 skipped in 126.49s
```

The 8 skips are the PostgreSQL profile (`SIS_POSTGRES_DSN` unset) and the
live Codex adapter. Both are opt-in by design; neither may be silently
counted as passing.

## Reproduced P0 defects

`tools/reproduce_v340_defects.py` drives the real production stack —
signed execution identity, committed authorization receipt, shared
control plane — and reports whether each attack is accepted.

```
OPEN   D1_cross_principal_outcome
       observed={'accepted': True, 'status': 200}
OPEN   D2_cross_repository_receipt
       observed={'accepted': True, 'status': 200,
                 'receipt_repo': '9999...9999', 'served_repo': 'repo-1'}
OPEN   D3_receipt_reuse_across_attempts
       observed={'accepted_submissions': 2}
open defects: 3
```

Each defect is pinned by a test in
`tests/v3/test_v340_p0_reproduction.py` marked
`xfail(strict=True)`. The marker is removed in the PR that closes the
defect; it is never relaxed. A strict xfail that starts passing fails the
suite, which is the intended reminder.

### Root causes

| Defect | Location | Cause |
|---|---|---|
| D1 | `serving_service.py:_outcome` | The authenticated requester is resolved and then dropped; `record_outcome` is called without it. |
| D2 | `serving.py:record_outcome` | Receipt verification compares only `task_id` and `outcome`; repository, tree, commit and attempt are not part of the comparison. |
| D3 | `serving.py` + `control_plane.py` | `authorization_for_task()` is a fallback when `authorization_id` is omitted, and `guidance_outcome` is keyed only by `authorization_id`, so one receipt can be inserted under two authorizations. |

## Legacy-evidence quarantine

Everything recorded before the V2 chain is **legacy evidence**. It stays
readable for audit but is never independent evidence:

- `guidance_outcome` rows carry `evidence_class = legacy_unverified`.
- Only the `outcome_v2` chain (PR-03) carries `evidence_class =
  verified`, and only verified rows may contribute to candidate
  promotion or to a confirmatory evaluation certificate.
- A mixed dataset is not promoted to confirmatory: an analysis that
  combines legacy and verified rows is reported as `exploratory`.

This is enforced in code by `LEGACY_EVIDENCE_CLASS` /
`VERIFIED_EVIDENCE_CLASS` in `sis.v3.control_plane` and by the
`independent_outcomes()` accessor, which reads only the verified chain.
