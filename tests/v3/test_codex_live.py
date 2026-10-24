"""SIS3-330: LIVE Codex adapter qualification (v3.3.0).

These tests exercise the real installed ``openai-codex==0.163.0`` SDK against
an authenticated Codex backend in a disposable workspace with read-only
sandboxing. They are NOT mocks: every assertion derives from streamed
``item/started``/``item/completed``/``turn/*`` notifications, real thread
IDs, and real interruption behavior.

Gated by ``SIS3_LIVE_CODEX=1`` so they never run silently in CI. When the
SDK, credentials, or quota are unavailable the class skips with a BLOCKED
reason — see docs/v3/CODEX_ADAPTER.md for the exact runbook.
"""
import os
import tempfile
import time
import unittest
from pathlib import Path

LIVE = os.environ.get("SIS3_LIVE_CODEX") == "1"


@unittest.skipUnless(
    LIVE,
    "BLOCKED: live Codex qualification requires SIS3_LIVE_CODEX=1 plus "
    "installed openai-codex SDK and authenticated Codex credentials",
)
class LiveCodexAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import openai_codex  # noqa: F401
            from sis.v3.adapters.codex import CodexAdapter
        except ImportError as exc:
            raise unittest.SkipTest(f"BLOCKED: SDK import failed: {exc}")
        cls._tmp = tempfile.TemporaryDirectory()
        cls.workspace = Path(cls._tmp.name) / "ws"
        cls.workspace.mkdir()
        (cls.workspace / "README.md").write_text("disposable probe repo\n")
        cls.adapter = CodexAdapter()
        try:
            client = cls.adapter._get_client()
            client.account()  # raises when unauthenticated
        except Exception as exc:
            raise unittest.SkipTest(
                f"BLOCKED: Codex client/auth unavailable: "
                f"{type(exc).__name__}: {str(exc)[:160]}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.adapter.close()
        except Exception:
            pass
        cls._tmp.cleanup()

    def _drain(self, turn, limit=120):
        events = []
        for event in turn.events:
            events.append(event)
            if len(events) >= limit:
                break
        return events

    def test_01_thread_start_and_typed_stream(self):
        turn = type(self).adapter.start_task(
            "Reply with exactly the text SIS_LIVE_OK and nothing else.",
            self.workspace, sandbox="read_only",
        )
        self.assertTrue(turn.thread_id)
        self.assertTrue(turn.turn_id)
        events = self._drain(turn)
        self.assertGreaterEqual(len(events), 2)
        # Event lineage: monotonically increasing seq, digest-chained.
        self.assertEqual([e.seq for e in events], list(range(len(events))))
        self.assertIsNone(events[0].prior_event_digest)
        for prev, cur in zip(events, events[1:]):
            self.assertEqual(cur.prior_event_digest, prev.digest)
            self.assertEqual(cur.episode_id, prev.episode_id)
        # Untrusted content is structurally summarized, never embedded raw.
        self.assertTrue(all(
            e.payload.get("raw_content_included") is False for e in events))
        self.assertTrue(all(
            e.payload.get("source_sdk") == "openai-codex-python"
            for e in events))
        type(self).THREAD_ID = turn.thread_id

    def test_02_resume_thread_preserves_lineage(self):
        thread_id = getattr(type(self), "THREAD_ID", None)
        if not thread_id:
            self.skipTest("no thread from earlier test")
        resumed = type(self).adapter.resume_thread(
            thread_id, self.workspace, sandbox="read_only")
        self.assertEqual(resumed, thread_id)
        turn = type(self).adapter.stream_turn(
            thread_id, "Reply with exactly RESUMED_OK and nothing else.")
        events = self._drain(turn)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0].episode_id,
                         "codex-episode-" + __import__("hashlib").sha256(
                             thread_id.encode()).hexdigest()[:32])

    def test_03_interrupt_terminates_stream(self):
        thread_id = getattr(type(self), "THREAD_ID", None)
        if not thread_id:
            self.skipTest("no thread from earlier test")
        turn = type(self).adapter.stream_turn(
            thread_id,
            "Write a 5000-word essay about the history of computing, "
            "section by section, without stopping.")
        iterator = iter(turn.events)
        first = next(iterator, None)
        self.assertIsNotNone(first)
        type(self).adapter.cancel(turn.turn_id)
        # After interrupt, the stream must END (finite) — a hanging
        # iterator means the interrupted process was not cleaned up.
        deadline = time.monotonic() + 90
        remainder = []
        while time.monotonic() < deadline:
            nxt = next(iterator, None)
            if nxt is None:
                break
            remainder.append(nxt)
        else:
            self.fail("interrupted turn stream did not terminate")
        self.assertLess(len(remainder), 400)

    def test_04_external_message_is_bounded_and_untrusted(self):
        thread_id = getattr(type(self), "THREAD_ID", None)
        if not thread_id:
            self.skipTest("no thread from earlier test")
        turn = type(self).adapter.send_external_message(
            thread_id,
            "SIS guidance probe: no applicable procedure (abstain).",
        )
        events = self._drain(turn, limit=60)
        self.assertGreaterEqual(len(events), 1)
        self.assertTrue(all(
            e.payload.get("raw_content_included") is False for e in events))


if __name__ == "__main__":
    unittest.main()
