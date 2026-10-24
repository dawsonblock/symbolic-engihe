# SIS v3 trust boundaries (M0)

## Intended target boundary

```text
Codex agent (restricted credentials)
  | read-only guidance; untrusted observation events
  v
SIS gateway / qualified-procedure reader
  | candidate artifacts only
  v
Offline learner and candidate store

Agent workspace -> isolated workspace worker -> immutable artifacts
                                      |
                                      v
                         independent outcome evaluator
                         private tests and signing key
                                      |
                                      v
                         operator governance controller
                                      |
                                      v
                         qualified procedure revisions
```

The agent-facing path must not expose evaluator-private fixtures, labels,
signing credentials, promotion APIs, or mutable qualified evidence. The worker
must not inherit SIS service credentials. A future operator must approve a
procedure only after independently verified evidence and retain a reversible
history.

## What exists in this M0 branch

- `sis.v3.contracts` defines bounded v1 data structures and canonical digests.
- `sis.v3.policy` defines a default-deny role/action matrix, assuming callers
  obtain roles from a trusted identity source.
- `sis.v3.guidance.sis_recommend` returns a bounded abstention because there
  is no v3 qualified procedure catalog.
- The v2 HTTP server has an explicit POST route inventory. Keyed deployments
  require the API key for reads and the distinct admin key for all listed
  operator mutations. Unkeyed loopback mutations remain available for the
  legacy demo.
- The v2 SQLite schema is unchanged; no v3 records are persisted.

## What is not established

The v3 policy module does not create distinct OS users, processes, credentials,
containers, VMs, or storage. `unverified_local` in a task envelope is an
explicit label, not a secure isolation profile. Hashes and record schemas do
not establish who created the record. The HTTP server's existing loopback demo
mode is not appropriate for multi-user or deployed use. No external audit
anchor, evaluator service, signer custody, key revocation, or task-admission
service is implemented.

## Separation requirements for later phases

1. Resolve agent, runner, learner, evaluator, and operator identities outside
   caller-controlled payloads.
2. Put hidden fixtures and signing keys under evaluator-only OS credentials.
3. Execute untrusted repository content only in a separately isolated worker
   with explicit resource and network limits.
4. Store verifier receipts and content-addressed artifacts under permissions
   unavailable to agent and learner identities.
5. Anchor audit heads outside the database's write authority.
6. Keep retrieval read-only and fail closed on stale context, missing evidence,
   incompatible lockfiles, revoked signers, or corrupt artifacts.

These are design requirements, not completed M0 controls.
