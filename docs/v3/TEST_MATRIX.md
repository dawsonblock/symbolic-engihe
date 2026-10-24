# SIS v3 test matrix and baseline evidence

## Frozen source identity

- Planned source archive: `symbolic-induction-engine-v2.4.0-codex-sis-v3-m0.zip`
- Planned archive SHA-256: `5ef4a01f63f3d9b95619f89f06769c955e9d1816ea97b0c90d12ecffca00244c`
- Exact archive status: **not locally present; ZIP hash not independently verified**.
- Working base commit: `daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08`.
- Baseline source manifest: 138 hashed files; verified from the pinned Git baseline.
- Baseline source manifest SHA-256: `8111357fe4ce96f458877eaedaf3defcf5254ea76edaa01a8d9ce9a954629266`.

The pinned Git tree is the working source basis. It is not represented as proof
that the absent ZIP is byte-identical. `SOURCE_SHA256.json` is intentionally not
regenerated during development.

## Baseline and current test coverage

| Check | Baseline expectation/evidence | Current M0 status |
|---|---|---|
| Existing unittest suite | 338 tests, 1 skip on the pinned v2.4.0 Git baseline | 363 tests, 1 skip after M0 changes; exact command/result in `STATUS.md` |
| CLI/HTTP integration smoke | Passed from extracted pinned Git baseline | Passed after M0 changes; exact command/result in `STATUS.md` |
| Source manifest | 138 source files verified at pinned baseline | Baseline mode verifies pinned Git blobs and reports dev delta separately |
| v3 contracts | Not present in baseline | Round-trip, unknown-field, duplicate-key, size, digest, path, and precondition tests |
| Authorization | Existing keyed HTTP separation | Full POST route matrix, forged JSON role, route aliases, and legacy loopback compatibility |
| Negative transfer | Legacy local Sub-to-Add preview can misapply to `remaining_balance` | False preview reproduced; new v3 guidance abstains with `unverified_task_intent` |

## Runtime matrix

CI is configured for Ubuntu Python 3.10, 3.12, and 3.13, plus Windows Python
3.12. These are configured jobs, not results until the workflow actually runs.
The local run uses the Python and operating system values recorded in
`STATUS.md`. Windows ACL behavior, live Codex SDK events, real Codex runs,
Docker/Podman/microVM isolation, and external custody are not verified here.

## Interpreting tests

Contract tests validate parsing, canonical identity, and bounds. Policy tests
validate the code-level matrix. HTTP tests validate the current local server
credential checks and compatibility behavior. None of these tests prove that
roles correspond to different OS principals, signatures have an independent
custodian, hostile code is contained, or SIS improves coding-agent outcomes.
