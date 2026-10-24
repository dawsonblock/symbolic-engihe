# SIS v3 implementation status

Current classification: **M0 implementation tested; its exact source-artifact
gate remains blocked because the named ZIP is not available in the workspace.
The SIS3-004 Codex adapter slice is implemented and locally tested, while live
SDK integration remains unverified.** Work uses the pinned v2.4.0 Git baseline
recorded below. SIS3-003, the durable event store, evaluator custody, procedure
qualification, and efficacy evaluation are not implemented.

## SIS3-001 and SIS3-002 report

```yaml
phase_id: SIS3-001+SIS3-002
status: blocked
base_revision: daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08
source_files_changed:
  - .github/workflows/ci.yml
  - pyproject.toml
  - src/sis/server.py
  - tools/check_source_manifest.py
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/MIGRATION.md
  - docs/v3/STATUS.md
  - docs/v3/TEST_MATRIX.md
  - docs/v3/THREAT_MODEL.md
  - docs/v3/TRUST_BOUNDARIES.md
  - examples/v3/contracts_v1.json
  - examples/v3/negative_transfer/remaining_balance.json
  - src/sis/v3/__init__.py
  - src/sis/v3/contracts.py
  - src/sis/v3/guidance.py
  - src/sis/v3/policy.py
  - tests/v3/__init__.py
  - tests/v3/test_contracts.py
  - tests/v3/test_guidance.py
  - tests/v3/test_http_permissions.py
  - tests/v3/test_policy.py
  - tests/v3/test_source_manifest.py
tests_added: 25
commands_run:
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 tools/check_source_manifest.py --baseline-ref daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08"
  - "python3 -m compileall -q src/sis tests/v3"
  - "Isolated temporary venv: pip install -e .; import sis, sis.v3"
  - "Extracted Git baseline: unittest, smoke integration, and source manifest checks"
observed_outcomes:
  - "Baseline at base_revision: 338 tests, 1 skipped; smoke passed; 138 manifest files verified"
  - "Development tree: 363 tests, 1 skipped; smoke passed; compileall passed"
  - "Pinned baseline integrity: 138 files verified; development delta reported separately"
  - "Editable install passed; imported SIS 2.4.0 and v3 schema version 1"
  - "The plan's exact ZIP SHA-256 was not verified because that ZIP is absent"
environment_and_dependency_versions:
  - "macOS 26.2"
  - "Python 3.12.0"
  - "setuptools 82.0.1 (pinned build backend)"
security_tests:
  - "All 12 operator POST routes denied a keyed reader token and forged JSON role"
  - "Unknown route aliases returned 404; query alias remained subject to operator authentication"
  - "Unkeyed loopback code-study compatibility passed in a disposable temporary database"
  - "Contract unknown fields, duplicate keys, non-finite numbers, oversized JSON, invalid paths, and executable preconditions rejected"
  - "Legacy Sub-to-Add preview reproduced the remaining_balance false transfer; v3 guidance abstained with unverified_task_intent and no procedure IDs"
remaining_unknowns:
  - "Exact planned archive symbolic-induction-engine-v2.4.0-codex-sis-v3-m0.zip and SHA-256 5ef4a01f63f3d9b95619f89f06769c955e9d1816ea97b0c90d12ecffca00244c remain unverified"
  - "GitHub CI was configured but not observed running; Windows and Python 3.10/3.13 were not tested locally"
  - "No real Codex SDK integration/run, isolated hostile-code execution, evaluator custody, signed receipt verification, external anchor, or efficacy experiment"
  - "The existing v2 sis_code_preview remains experimental and can still propose the known false transfer"
next_gate: "Verify the exact source archive identity and review M0 evidence before starting M1"
```

## Gate interpretation

The implementation and local tests are complete for the first two tickets, but
the overall M0 gate remains blocked on the planned archive identity. The pinned
Git source manifest and extracted Git baseline were independently checked in
this workspace; this does not substitute for verifying the absent ZIP hash.
No claim is made about live Codex capture, hostile-code containment, qualified
procedures, or improved coding-agent outcomes.

## SIS3-004 Codex adapter implementation slice

```yaml
phase_id: SIS3-004-adapter-slice
status: tested
base_revision: f001ade3110f6e5954488b72af228469569087c6
source_files_changed:
  - pyproject.toml
  - src/sis/v3/contracts.py
  - src/sis/v3/adapters/__init__.py
  - src/sis/v3/adapters/base.py
  - src/sis/v3/adapters/codex.py
  - tests/v3/test_codex_adapter.py
  - docs/v3/CODEX_ADAPTER.md
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/STATUS.md
tests_added: 8
commands_run:
  - "PYTHONPATH=src python3 -m unittest tests.v3.test_codex_adapter -v"
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 tools/check_source_manifest.py --baseline-ref daf0ccc"
  - "python3 -m compileall -q src/sis/v3/adapters tests/v3/test_codex_adapter.py"
  - "python3 -m pip install --dry-run '.[codex]'"
  - "python3 -m pip wheel --no-deps --no-build-isolation -w /tmp/sis-codex-adapter-wheel ."
  - "python3 -c 'import glob, zipfile; wheels=glob.glob(\"/tmp/sis-codex-adapter-wheel/*.whl\"); assert len(wheels)==1; names=set(zipfile.ZipFile(wheels[0]).namelist()); expected={\"sis/v3/adapters/__init__.py\", \"sis/v3/adapters/base.py\", \"sis/v3/adapters/codex.py\"}; assert expected <= names'"
  - >-
    PYTHONPATH=/Users/dawsonblock/Downloads/codex-main/sdk/python/src:src python3 -c 'import inspect, openai_codex; from sis.v3.adapters import AgentTurn, CodexAdapter; from openai_codex import Codex, ExternalMessage, Sandbox; assert "thread_start" in dir(Codex) and "thread_resume" in dir(Codex); assert "turn" in dir(openai_codex.Thread); assert "stream" in dir(openai_codex.TurnHandle) and "interrupt" in dir(openai_codex.TurnHandle); assert Sandbox.__members__["workspace_write"]; assert ExternalMessage.__init__; print("source_sdk_version=" + openai_codex.__version__); print(inspect.signature(openai_codex.Thread.turn)); print("public API surface check passed")'
observed_outcomes:
  - "Adapter tests passed: 8 tests; the full SIS suite passed: 371 tests, 1 skipped"
  - "CLI/HTTP smoke passed; this is local integration evidence only"
  - "Pinned pristine baseline: 138 source files verified; development delta reported separately"
  - "Optional dependency resolved to openai-codex 0.163.0 and openai-codex-cli-bin 0.163.0"
  - "Built wheel contains all three sis.v3.adapters package files"
  - "Built wheel SHA-256: 602b05952f70f7ed694c80510433f59d453728cd8035e0cff387d4ad5416a191"
  - "Provided SDK source imports as 0.0.0-dev and exposes typed thread, turn, interrupt, sandbox, and ExternalMessage APIs"
environment_and_dependency_versions:
  - "macOS 26.2"
  - "Python 3.12.0"
  - "Provided SDK checkout: openai-codex 0.0.0-dev; CLI binary requirement 0.153.4"
  - "Build extra: published openai-codex==0.163.0; dependency resolution dry-run only"
security_tests:
  - "SDK event summaries omit prompt/assistant text, command/output content, terminal input, diffs, and paths"
  - "Default Codex sandbox is read-only; adapter rejects full_access"
  - "External SIS content is passed through SDK ExternalMessage with tool-level provenance"
  - "The adapter has no direct command runner, evaluator-state writer, or signing API; Codex handles tool execution under its configured permissions"
remaining_unknowns:
  - "No authenticated live Codex task was run; wheel install and SDK runtime behavior remain unverified"
  - "The supplied Codex source directory has no Git revision; adapter targets its public API and pins the published SDK separately"
  - "Workspace-write is a Codex permission preset, not a validated OS isolation boundary"
  - "Commands are observed by event type and exit state; the adapter does not classify whether command text invoked tests"
  - "No durable event store, replay/recovery, source snapshot collector, independent verifier, or signed outcome receipt exists yet"
  - "M0's exact source archive and SHA-256 remain unavailable and unverified"
next_gate: "Run one controlled authenticated task in a disposable workspace, then implement durable event capture and exact workspace snapshot collection before claiming M1 complete"
```
