# Codex SDK adapter (SIS v3, experimental)

SIS's Codex adapter uses the public `openai-codex` Python SDK to start or
resume a thread, stream typed turn events, request interruption, and deliver
bounded untrusted SIS context as an SDK `ExternalMessage`. Codex remains the
coding agent. SIS does not execute repository code or grade the agent's result.

Install the optional integration extra when needed:

```sh
python -m pip install -e '.[codex]'
```

Example:

```python
from sis.v3.adapters import CodexAdapter

with CodexAdapter() as adapter:
    turn = adapter.start_task(
        "Inspect the failing behavior, then fix it and run the relevant tests.",
        "/path/to/disposable/workspace",
        sandbox="workspace_write",
    )
    # A controller may call adapter.cancel(turn.turn_id) while the stream is live.
    for event in turn.events:
        print(event.event_type, event.payload["sdk_method"], event.digest)
```

The adapter defaults to `read_only`; `workspace_write` must be explicitly
selected. These are Codex access presets. They do not establish OS isolation,
contain hostile repository code, or substitute for the separate evaluator
worker required by the plan. `full_access` is deliberately not exposed by this
adapter.

The first adapter version stores only bounded structural summaries from SDK
events: method, event/item type, status, exit code, token counts, and content or
change counts where available. It omits prompt text, assistant text, terminal
input, tool commands and output, diffs, and file paths.
The resulting `ObservationEventV1` values are still local observations. There
is no durable append-only event store, filesystem/Git snapshot collector,
replay recovery, independent verifier, or signed outcome receipt in this
adapter. SIS guidance is not injected automatically. If a caller explicitly
uses `send_external_message`, the SDK receives it as tool-level untrusted
content; that conveys neither user authorization nor policy authority.

The provided `codex-main/sdk/python` checkout reports version `0.0.0-dev` and
pins its development CLI binary separately. It has no usable Git revision in
the supplied directory, so the build does not depend on that absolute local
path or vendor the Codex source tree. The optional extra pins the published
`openai-codex` wheel to `0.163.0`; the adapter's source-API behavior is covered
with fake clients, while compatibility with that wheel and an authenticated
live Codex run remain unverified here.

## v3.3.0 live qualification (observed 2026-10-24)

Executed `SIS3_LIVE_CODEX=1 PYTHONPATH=src python3 -m pytest -q
tests/v3/test_codex_live.py` against the real installed
`openai-codex==0.163.0` SDK (bundled `openai-codex-cli-bin==0.163.0`):

- **4 passed in 15.01s** — authenticated ChatGPT account (plus tier).
- Real `thread_start` in a disposable workspace under
  `Sandbox.read_only`; typed notifications (`turn/started`,
  `item/started`, `item/agentMessage/delta`, `item/completed`,
  `thread/tokenUsage/updated`) streamed and normalized into digest-chained
  `ObservationEventV1`s (`seq` ordered, `prior_event_digest` linked,
  `raw_content_included=False` on every event).
- `thread_resume(thread_id)` returned the same thread id; a second turn
  on the resumed thread preserved episode lineage
  (`codex-episode-<sha256(thread_id)[:32]>`).
- `adapter.cancel(turn_id)` interrupted a running long-form turn; the
  event iterator terminated (verified cleanup, not just a cancel request).
- `send_external_message` delivered bounded text as SDK `ExternalMessage`;
  events remained structural-only.

Runbook to reproduce: install `.[codex]`, ensure `~/.codex/auth.json`
contains a valid login (or `codex login`), then
`SIS3_LIVE_CODEX=1 PYTHONPATH=src python3 -m pytest -q tests/v3/test_codex_live.py`.
Without the env var the class skips with a BLOCKED reason; mocked tests
must never be reported as this qualification.

## Retention and privacy boundary

- SIS-side logs record only bounded structural summaries — event types,
  bounded status fields, digests — never prompt text, diffs, paths, or
  tool output.
- Codex-side: `thread_resume` succeeding demonstrates that thread history
  IS retained by the provider/SDK. SIS makes no guarantee that Codex or
  its provider forgets content; treat every prompt, file, and tool result
  sent to a turn as provider-retained.
- The adapter's `read_only`/`workspace_write` sandbox presets are SDK
  presets, not an SIS security boundary; evaluator credentials, private
  test fixtures, and promotion state are never placed in the workspace.

## Negative permission probes (static, verified in unit tests)

Guidance content is delivered as `ExternalMessage` at tool-level
authority — it cannot issue evaluator commands, mutate promotion or
candidate state, or escape the SDK sandbox. Agent-supplied text is
bounded (`_MAX_EXTERNAL_CHARS`) and summarized structurally only.
