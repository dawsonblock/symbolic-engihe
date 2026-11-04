# SIS v3.4.0 operator runbook

> v3.5.0 adds a mandatory production profile and custody/crypto
> checks. See `V350_IMPLEMENTATION.md` for the current status and
> `V350_BASELINE.md` for the measured baseline.

Every command below runs from the tree root with `PYTHONPATH=src:.`.

## 1. Pre-flight

```
python3 tools/check_runtime.py
```

Exits non-zero when the interpreter or a pinned dependency differs from
`requirements-lock.txt`. A result measured in a drifted environment is not
a pinned-runtime result.

```
python3 -m pytest -q
```

Expected, SQLite profile: **1346 passed, 12 skipped**.
Expected, PostgreSQL profile: **1355 passed, 3 skipped** (measured on
PostgreSQL 14.20 with the commands below). The 9 tests that only run
with a DSN are the multi-replica profile; a green SQLite run says
nothing about them.

Run both before a release. The 7 extra tests in the PostgreSQL run are the
multi-replica profile; a green SQLite run says nothing about them — it did
not catch the placeholder and integrity-error defects in this branch.

```
initdb -D /tmp/sis-pg -A trust -U sis
pg_ctl -D /tmp/sis-pg -o "-p 55432 -k /tmp/sis-pg" start
createdb -h /tmp/sis-pg -p 55432 -U sis sis_test
SIS_POSTGRES_DSN="host=/tmp/sis-pg port=55432 user=sis dbname=sis_test" \
  python3 -m pytest -q
```

Use a disposable database: the profile tests drop their own tables.

## 2. Key custody

Four identities, four seeds, owner-only permissions:

| Role | Signs |
|---|---|
| `agent` | nothing — it executes |
| `serving_authority` | `AuthorizationV2` |
| `evaluator` | `EvaluatorReceiptV2` |
| `promotion_authority` | promotion/revocation decisions |

```python
from sis.v3.key_custody import four_identity_custody
custody = four_identity_custody("/var/lib/sis/keys")
print(custody.custody_report())
```

`custody_report()["ready"]` is false unless the evaluator and serving
keys exist and every enrolled seed is `0600`. Two roles sharing a key is a
hard failure: the evaluator could then mint promotion evidence.

## 3. Authority ledger

```python
from sis.v3.authority_ledger import AuthorityLedger
ledger = AuthorityLedger(control_plane, signing_key=custody_key)
ledger.set_candidate_status("cand-1", "qualified")
snapshot = ledger.publish()          # signed, epoch-pinned
print(ledger.readiness())
```

`readiness()` is false when the epoch has moved past the last published
snapshot, when the stored snapshot does not verify against the ledger's
own public key (`snapshot_verified`), or when the global disable is set.
A stale or unverifiable snapshot is an authority inconsistency, not a
cosmetic warning. The ledger refuses to sign snapshots with the same key
the control plane uses for authorizations.

## 4. Kill switch

```python
control_plane.set_global_disable(True, reason="incident")
```

Effective on the next request on every replica: `serve()` reads the flag
from the shared store each time, and `authorize_bound` re-reads it inside
the committing transaction. Re-enable with
`set_global_disable(False)`.

Verify:

```
curl -s localhost:8765/livez    # 200 while the process answers
curl -s localhost:8765/readyz   # 503 while disabled or degraded
curl -s -H "X-SIS-Key: $SIS_API_KEY" localhost:8765/readyz   # adds checks
```

`/livez` is liveness only — never restart a process because `/readyz`
failed. `/readyz` is readiness to issue guidance.

## 5. Monitoring

```python
from sis.v3.operations import AuthorityMonitor
report = AuthorityMonitor(control_plane=plane, ledger=ledger,
                          custody=custody).scan()
```

`report["serving_allowed"]` is false when any `critical` finding exists.
Critical findings: control plane unreadable, evidence unreadable, a
revoked signer that authorized guidance, shared custody identity, seed
permissions wider than `0600`.

Pass the monitor to the gateway and a critical finding gates readiness:

```python
gateway = GovernedServingGateway(..., monitor=monitor)
gateway.health()["checks"]["authority_monitor"]   # {"ok": False, ...}
```

The scan is a readiness check, not a per-request gate; `serve()` reads
the kill switch, not the full scan. It is cached for 30 seconds
(`AuthorityMonitor(..., cache_seconds=30)`); call `refresh()` during an
incident to force a new report.

## 6. Migration and rollback

```
python3 tools/migrate_control_plane.py --db sis-control-plane.db --to 3
python3 tools/migrate_control_plane.py --db sis-control-plane.db --to 1 --yes
```

Upgrades are additive and idempotent. A downgrade drops the tables a later
schema introduced; it takes a verified backup first and refuses without
`--yes`. For PostgreSQL, run the same package version against the database
(the tables are created at startup) and take a `pg_dump` before any
downgrade.

## 7. Recovery drills

Run these before trusting a deployment:

1. **Kill switch survives restart** — disable, restart, re-read state.
2. **Epoch survives restart** — record the epoch, restart, re-read.
3. **Torn commit leaves no authorization** — a nonce row without an
   authorization row must still refuse a replay.
4. **Migration round-trip** — downgrade to 1, upgrade to 3, verify tables.
5. **Custody drift** — widen a seed's mode, confirm a critical finding.

All five are encoded in `tests/v3/test_v340_operations.py`.

## 8. Staged rollout

```python
from sis.v3.rollout import SHADOW, ADVISORY, FULL, advance, evaluate
state = evaluate(gate_status, stage=SHADOW)   # serves nothing
state = advance(SHADOW, ADVISORY, gate_status)
state = advance(ADVISORY, FULL, gate_status)
```

- `shadow` — observe and record, deliver nothing.
- `advisory` — deliver advisory text, grant no procedures.
- `full` — recommend under the normal authority gates.

A gateway given the state enforces it (`serve()` abstains with
`rollout_shadow` in the shadow stage and suppresses procedure grants in
the advisory stage). A missing gate is a failed gate. Rollback is always
available, is one step at a time, and keeps the gate status it was given:

```python
state = rollback(FULL, reason="incident", status=last_gate_status)
```

## 9. Release provenance

```
python3 tools/verify_release.py .
```

Verifies every file in the tree against `RELEASE_SHA256.json`; exits
non-zero on any mismatch. The release is not shippable unless this
passes and the artifact is built from the verified tree.

## 10. Incident: guidance looks wrong

1. Disable the kill switch.
2. Run the monitor; capture `findings` and `counts`.
3. Check `control_plane.legacy_outcomes()` — if any exist, analysis that
   mixes them with verified outcomes is exploratory.
4. `gateway.recheck(authorization_id)` on any in-flight authorization to
   confirm it is still valid before any delayed delivery.
5. Re-enable only after `serving_allowed` is true.
