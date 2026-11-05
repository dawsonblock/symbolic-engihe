# SIS v3.5.1 — Reproduction Instructions

Every command below was executed on the release host and its result is
recorded in `qualification/qualification.json`.

## 1. Environment

Verified on:

```
Python 3.12.0 (main, Apr 26 2026) [Clang 21.0.0]  aarch64-darwin
Docker 29.9.2 (Desktop)
PostgreSQL 14.20 (Homebrew)
```

Required:

| Component | Version | Why |
|---|---|---|
| Python | 3.12 (3.10+ supported) | runtime |
| pytest | 8.4.2 | test runner |
| hypothesis | 6.151.4 | property-based totality tests |
| cryptography | 48.0.1 | vetted Ed25519 backend; production refuses the vendored fallback |
| psycopg[binary] | 3.3.4 | PostgreSQL profile |
| setuptools | 82.0.1 | packaging |

## 2. Install

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m pip install -e . --no-deps
```

The core package has no runtime dependencies. `psycopg` is needed only
for the PostgreSQL profile; `cryptography` is needed for any production
claim.

## 3. Run the suite

```bash
PYTHONPATH=src:. python -m pytest tests -q
# expected: 1498 passed, 3 skipped (with SIS_POSTGRES_DSN and
#           SIS_POSTGRES_ALLOW_DESTRUCTIVE=1 set)
#           or 1484 passed, 17 skipped (without)
```

The 14-test difference is the PostgreSQL profile. A skip is **not** a
pass.

## 4. PostgreSQL qualification

```bash
initdb -D /tmp/sis-pgdata -A trust -U postgres
pg_ctl -D /tmp/sis-pgdata -l /tmp/sis-pg.log \
       -o "-p 55499 -k /tmp/sis-pgsock -c listen_addresses=127.0.0.1" start
createdb -h 127.0.0.1 -p 55499 -U postgres sis_v351

export SIS_POSTGRES_DSN="postgresql://postgres@127.0.0.1:55499/sis_v351"
# The qualification fixture drops the control-plane tables. This is the
# operator's explicit statement that the database may be destroyed.
export SIS_POSTGRES_ALLOW_DESTRUCTIVE=1
PYTHONPATH=src:. python -m pytest tests/v3/test_control_plane_postgres.py \
    tests/v3/test_v351_postgres_qualification.py -q
# expected: 10 passed
```

`test_v351_postgres_qualification.py` spawns four OS processes; they
must produce exactly one commit.

## 5. Container isolation qualification

```bash
docker pull python:3.12-slim          # or set SIS_CONTAINER_IMAGE
PYTHONPATH=src:. python -m pytest tests/v3/test_v351_container_isolation.py -q
# expected: 23 passed
```

Each test attempts an escape: network connect, host file read, signing
key read, root write, fork bomb, memory overrun, hang. Without a
container runtime the file skips with an explicit reason and the
qualification harness reports the gate as **blocked**.

## 6. The adversarial evidence tests

```bash
PYTHONPATH=src:. python -m pytest tests/v3/test_v351_evidence_chain.py -q
# expected: 57 passed
```

The v3.5.0 baseline is not reproducible by checking out one file: the
v3.5.1 fixtures pass `measurement=` to `ArmOutcome` and import
`authorize_experiment`, neither of which exists at `9491047`. The
baseline observations in `SIS_v3.5.1_DEFECT_MATRIX.md` were made in a
separate worktree at that commit with a small script that swaps two
genuine `ArmOutcome` objects and recomputes the aggregate; they are
recorded as observations, not as a runnable harness.

## 7. Full qualification harness

```bash
SIS_POSTGRES_DSN="postgresql://postgres@127.0.0.1:55499/sis_v351" \
    python tools/v351_qualify.py --with-postgres
```

Writes `qualification/qualification.json` and one log per gate. The
decision is computed from the gates:

* any `fail` → `NO_GO`
* any `blocked` → `CONDITIONAL_GO`
* every gate `pass` and no blocking limitation → `GO`
* every gate `pass` but a blocking limitation remains → `CONDITIONAL_GO`

The blocking limitations are `evaluator-key-compromise`,
`no-capability-evaluation` and `uncommitted-source`. The others are
declared risks that restrict the deployment scope without preventing a
clean release.

## 8. Release manifest

```bash
python tools/build_release.py --check     # must exit 0
python tools/verify_release.py .          # re-hashes every inventoried file
shasum -a 256 release/SIS_v3.5.1_FULL_UPGRADED.zip \
              release/SIS_v3.5.1_VALIDATION_EVIDENCE.zip
```

`RELEASE_SHA256.json` is **locally generated and not publisher-signed**.
It detects drift; it does not establish authorship.

## 9. Rebuilding the archives

```bash
python tools/build_release.py             # regenerate the inventory
python tools/package_release.py \
    --release SIS_v3.5.1_FULL_UPGRADED \
    --status CONDITIONAL_GO --passed 1498 --skipped 3 --allow-dirty
```

`--allow-dirty` is required while the tree is uncommitted; the release
manifest and provenance statement record that state. A committed rebuild
omits it.

The evidence bundle is rebuilt from the qualification record:

```bash
python tools/build_evidence_bundle.py
python tools/build_evidence_bundle.py --verify \
    release/SIS_v3.5.1_VALIDATION_EVIDENCE.zip
```

## 10. Verifying a fresh extraction

```bash
unzip -q release/SIS_v3.5.1_FULL_UPGRADED.zip -d /tmp/sis-v351
cd /tmp/sis-v351/SIS_v3.5.1_FULL_UPGRADED
python tools/verify_release.py .
PYTHONPATH=src:. python -m pytest tests -q
```

This is the check that matters for a consumer: the archive must verify
against its own embedded manifest with no git history and no network.
