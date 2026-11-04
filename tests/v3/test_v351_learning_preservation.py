"""SIS v3.5.1 PR-11: the symbolic-learning path still works.

The security repair must not have broken learning. These tests re-assert
the reuse path end to end at the retrieval layer: a qualified,
evidence-backed procedure is retrieved and reused for the context it was
qualified in, and is *not* retrieved across a task, context,
qualification or revocation boundary.

They are deliberately narrow. The point is preservation, not new
capability: nothing here adds a reasoning module, and no model weights
are modified.
"""
from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sis.v3.retrieval import retrieve
from tests.v3.test_retrieval import _proc, _request, _store


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_a_qualified_procedure_is_reused_in_its_context(self):
        store = _store(_proc(), root=self.root / "a")
        result = retrieve(_request(), store)
        self.assertTrue(result.candidates, result.rejections)
        self.assertEqual(result.candidates[0].record.procedure_id, "p1")

    def test_reuse_does_not_cross_the_context_boundary(self):
        store = _store(_proc(), root=self.root / "b")
        # A different language is a different context; the same record
        # must not be offered for it.
        result = retrieve(_request(language="rust"), store)
        self.assertFalse(result.candidates, result.rejections)

    def test_reuse_does_not_cross_the_task_boundary(self):
        record = _proc(pre=({"kind": "symbol_present",
                             "value": "remaining_balance"},))
        store = _store(record, root=self.root / "c")
        self.assertTrue(retrieve(_request(), store).candidates)
        # The symbol the procedure requires is not in the new context.
        missing = retrieve(_request(present_symbols=()), store)
        self.assertFalse(missing.candidates, missing.rejections)

    def test_reuse_does_not_cross_the_qualification_boundary(self):
        store = _store(_proc(status="candidate"), root=self.root / "d")
        result = retrieve(_request(), store)
        self.assertFalse(result.candidates, result.rejections)

    def test_reuse_stops_when_the_record_expires(self):
        record = replace(_proc(), expires_at="2020-01-01T00:00:00Z")
        store = _store(record, root=self.root / "e")
        self.assertFalse(retrieve(_request(), store).candidates)
        # ...and resumes when time is injected before expiry.
        self.assertTrue(
            retrieve(_request(), store, now="2019-06-01T00:00:00Z").candidates)

    def test_reuse_stops_when_the_record_is_revoked(self):
        store = _store(_proc(), root=self.root / "f")
        served = retrieve(_request(), store)
        self.assertTrue(served.candidates)
        digest = served.candidates[0].record.digest
        revoked = retrieve(_request(), store, revoked=frozenset({digest}))
        self.assertFalse(revoked.candidates, revoked.rejections)


if __name__ == "__main__":
    unittest.main()
