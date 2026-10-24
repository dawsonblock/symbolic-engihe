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
| Workspace execution (SIS3-003) | Not present in baseline | Bounded runs, rlimit enforcement, capped output, kill switch, env scrub, symlink/disk audits, optional macOS seatbelt network/write denial; receipts honest about `unverified_local` |
| Episode store (SIS3-005) | Not present in baseline | Chained append, idempotent retry, conflict/missing-artifact rejection, crash-tail repair, tamper detection, head anchoring |
| Signed outcomes (SIS3-006) | Not present in baseline | Evaluator-custodied Ed25519 receipts verify offline; tamper/wrong-key/replay/duplicate rejected; roles denied; journal fails closed on corruption |
| End-to-end episode | Not present in baseline | Scripted-agent vertical through executor→store→verifier→replay; live Codex CLI contact captured (quota-limited turn.failed, correct fail receipt) — see docs/v3/episodes/live-001 |
| Procedure catalog (SIS3-007) | Not present in baseline | Digest-keyed append-only store; deterministic miner over verified episodes; learner role gate |
| Patch proposals (SIS3-008) | Not present in baseline | Unique-span byte replacement; CRLF/Unicode preserved; nonunique/missing/escape rejected; proposals are artifacts |
| Retrieval (SIS3-009) | Not present in baseline | All precondition kinds gated; contraindications→prior_negative_transfer; qualified-only; deterministic ranking |
| Guidance (SIS3-010) | Abstain-only | Recommend path with procedures+evidence+matched gates; remaining_balance fixture abstains prior_negative_transfer |
| Promotion (SIS3-011) | Not present in baseline | Full lifecycle; operator token + evaluator signature for evidence transitions; chained decision log; checkpoint/restore |
| Anchors (audit) | head export only | AnchorChain in separate-custody dir; grew/corrupt/missing divergence detection |
| Benchmark (SIS3-012) | Not present in baseline | Paired A/B/C/D harness, fresh workspaces, independent scoring, wins/losses/ties; Wilson CI95 per arm + exact McNemar p per pair |
| Release artifact (SIS3-101/102) | SOURCE manifest Git-pinned only | `RELEASE_SHA256.json` (229 files) + deterministic `build_zip` (byte-identical rebuilds) + ZIP-native `verify()` + `verify_tree`; tamper/extra/missing/duplicate/symlink/manifest-self-coverage rejected; `--attest` provenance record |
| Authoritative promotion (v3.1.1) | `allow_qualified` code bypass | Governed status only via signed decisions + `backing_decision` binding; intent-journal atomic commit w/ crash recovery; `EligibilitySnapshot` sole serving authority |
| Policy-gated serving (v3.2.0) | Raw `record.status` reads | Snapshot rebuilt per request; `ScopeGrantV1` signed repo/family/cross-repo grants; wrong-repo and revoked-evidence abstention; kill switch → `catalog_unavailable` |
| Outcome replay (v3.2.1) | Pure `verify_envelope` | `verify_and_consume` durable nonce ledger; spent envelopes cannot back second promotions; restart-surviving |
| Semantic checks closure (v3.2.1) | Same-class swaps presumed safe | AST flags every operator substitution/operand reorder/structural change; `a+b→a*b` now a violation |
| Live Codex adapter (v3.3.0) | Undocumented API risk | `openai-codex==0.163.0` public SDK; bounded `ObservationEventV1` envelopes; `SIS3_LIVE_CODEX=1` live suite 4/4 vs real backend |
| Typed repair induction (v3.4.0) | Generic workflow-text mining | `RepairHypothesisV1` AST templates + typed metavariables; mine→qualify→transfer across disjoint repos; counterexample contract failure → abstain |
| Held-out efficacy (v4.0.0) | Scripted agents only | Live Codex A-vs-D on 3 disjoint held-out repos + control: 1 win/0 losses/2 ties — directional, underpowered (`TRANSFER_EXPERIMENT.md`) |
| Episode projection (SIS3-122) | Not present in baseline | Deterministic replay projection; `agent_view` excludes evaluator payloads and artifact bytes |
| OutcomeEnvelopeV2 (SIS3-131) | V1 receipts only | Attempt/env/exec-receipt binding, nonce + expiry, pinned key registry w/ validity windows, revocation + replay rejected; V1 serialization unchanged |
| Semantic checks (SIS3-141) | Text-level negative transfer only | AST operator-class diff; noncommutative↔commutative swaps flagged (`remaining_balance` class protected); counterexample index surfaces corpus negatives |
| Catalog scopes (SIS3-150) | Single flat catalog | repository/family/cross_repository scopes persisted + scoped qualified head; `cascade_suspend` suspends all qualified records citing a revoked evidence digest via governed decisions |
| Guidance phases (SIS3-161) | Single abstain/recommend path | shadow (logs would-recommend, agent sees abstain), diagnostic (reasons only), conditional (full serve); kill switch via file + `SIS3_DISABLE`; acceptance telemetry logged, never a success label |
| Ablations (SIS3-171) | Not present in baseline | `AblationFlags` removes precondition/contraindication/qualification gates for benchmark arms; never default-on |

## Runtime matrix

CI is configured for Ubuntu Python 3.10, 3.12, and 3.13, plus Windows Python
3.12. These are configured jobs, not results until the workflow actually runs.
The local run uses the Python and operating system values recorded in
`STATUS.md`. Windows ACL behavior, live Codex SDK events, real Codex runs,
Docker/Podman/microVM isolation, and external custody are not verified here.

## Interpreting tests

Contract tests validate parsing, canonical identity, and bounds. Policy tests
validate the code-level matrix. HTTP tests validate the current local server
credential checks and compatibility behavior. Runner tests validate that the
local executor enforces its documented limits on this host — they do not prove
containment against adversarial code on arbitrary platforms. Verifier tests
validate signature correctness, custody separation of the key material, and
rejection paths — they do not prove the evaluator runs as a separate OS
principal. The verified-episode test proves the pipeline mechanics, not agent
efficacy: none of these tests prove that roles correspond to different OS
principals, signatures have an independent custodian, hostile code is
contained, or SIS improves coding-agent outcomes.
