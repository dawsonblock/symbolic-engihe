# SIS v3 evidence protocol (contract draft, v1)

## Record model

The authoritative Python validators are in `src/sis/v3/contracts.py`. Every
record uses `schema_version: 1`, rejects missing or unknown fields, limits its
canonical JSON to 64 KiB, rejects duplicate JSON keys, and bounds nested JSON
depth, node count, text, and collection sizes. Floating-point values are
excluded so cross-runtime canonicalization has fewer representation cases.

The contracts cover:

- `TaskEnvelopeV1`: task and repository digests, command capability IDs, actor,
  time/token/tool budgets, and an isolation profile. It contains no hidden test
  content. `permitted_commands` are identifiers for a future policy mapping,
  never shell strings.
- `ObservationEventV1`: episode/attempt sequence, observed kind, actor,
  timestamp, input/output and artifact digests, parent digest, idempotency key,
  payload digest, and bounded payload. `agent_event` represents a typed SDK
  event that is not safely classified as a tool call, edit, or completion.
- `PatchProposalV1`: source blob, normalized relative target path, exact span
  fingerprint, diff digest, purpose, procedure references, and evidence refs.
  It describes a proposal; it is not a write command.
- `ExecutionReceiptV1`: worker/environment identity, before/after tree hashes,
  command specification, exit state, bounded resource counters, and output
  hashes.
- `OutcomeReceiptV1`: evaluated tree, test-suite commitment, criterion,
  outcome, regression evidence, key ID, and signature-shaped field.
- `ProcedureRecordV1`: scoped language/task/failure signatures, structured
  preconditions and contraindications, plain-language steps, verification,
  counterexamples, evidence, status, and expiry.
- `PromotionDecisionV1`: candidate/protocol/receipt digests, actor, transition,
  policy version, rollback reference, and signature/authorization fields.
- `GuidanceRequestV1` and `GuidanceV1`: bounded context and a recommendation or
  abstention with exact evidence/policy references and at most three IDs.

Structured preconditions use an allowlisted `kind` and exact fields. The v1
validator does not accept Python, shell, or other executable expressions.
Procedure steps are informational text and are never executed by this module.

## Canonical identity

`canonical_json` sorts object keys, encodes UTF-8 without extra whitespace, and
rejects unsupported values. `canonical_digest(type, version, value)` computes:

```text
SHA256(UTF8("sis-v3:{type}:{version}\0") || canonical_json(value))
```

The domain prefix separates record types and schema versions. Event payload
digests are checked against the canonical payload. Digests identify content;
they do not establish semantic correctness, signer custody, or independence.

## Observations vs. outcomes

Agent statements, tool output, local test output, and candidate-reported
completion are observations. They are not evaluator labels. A future outcome
receipt must be created by an evaluator that runs fixed acceptance criteria on
the exact submitted repository tree. The evaluator's key must be unavailable
to agent, learner, and worker processes. An independent durable anchor and key
rotation/revocation policy are also required.

M0 defines the `OutcomeReceiptV1` shape only. It does not sign, verify, admit,
store, or externally anchor any receipt. The example signature and promotion
authorization values are explicitly illustrative placeholders.

## Idempotence and replay

Events carry stable IDs, an idempotency key, sequence, and prior digest. A
future append-only event store must enforce uniqueness and transactionally
reject sequence conflicts. Evaluation receipts need unpredictable per-run
identities, replay protection, exact artifact binding, signer key IDs, and
protocol-version checks; M0 does not implement those services.

## Current guidance behavior

The M0 guidance function is read-only and abstains because no v3 qualified
catalog exists. Without a verified semantic task contract it returns
`unverified_task_intent`. The `remaining_balance` fixture records the known
Sub-to-Add negative transfer and requires this abstention. Existing v2
`sis_code_preview` remains a separate experimental API and is not upgraded by
this contract phase.
