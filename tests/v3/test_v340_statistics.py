"""PR-09: power-derived sample sizes, preregistration and lineage holdouts."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.evaluation_certificate import QualificationValidator
from sis.v3.learning_qualification import analyze_report
from sis.v3.statistical_power import (
    CONFIRMATORY,
    EXPLORATORY,
    LineageRegistry,
    PowerRequirement,
    PreregistrationRegistry,
    RepositoryLineage,
    StatisticsError,
    check_lineage_holdout,
    classify,
    sign_preregistration,
)
from tests.v3.test_evaluation_certificates import (
    PROTOCOL_DIGEST,
    REPO,
    CertificateFixture,
)

REPO_REGISTRY_ID = "repo-1"
REGISTERED_AT = "2026-10-01T00:00:00Z"
EVALUATED_AT = "2026-10-26T00:00:00Z"


def power(effect=400, discordant=300, **overrides):
    fields = dict(design="paired_mcnemar", effect_milli=effect,
                  discordant_milli=discordant, alpha_milli=50,
                  power_milli=800)
    fields.update(overrides)
    return PowerRequirement(**fields)


class PowerTests(unittest.TestCase):
    def test_required_sample_size_is_monotone_in_the_effect(self):
        strong = power(effect=500).required_sample_size()
        weak = power(effect=100).required_sample_size()
        self.assertLess(strong, weak)

    def test_required_sample_size_is_monotone_in_power(self):
        low = power(power_milli=500).required_sample_size()
        high = power(power_milli=950).required_sample_size()
        self.assertLess(low, high)

    def test_required_sample_size_is_monotone_in_the_discordant_rate(self):
        low = power(discordant=100).required_sample_size()
        high = power(discordant=500).required_sample_size()
        self.assertLess(low, high)

    def test_a_declared_effect_reproduces_a_defensible_size(self):
        # A 10-point paired effect with 30% discordance needs far more
        # than the 29 tasks v3.3.2 would accept.
        self.assertGreater(power(effect=100, discordant=300)
                           .required_sample_size(), 100)

    def test_two_proportion_design(self):
        requirement = PowerRequirement(
            design="two_proportion", effect_milli=200, baseline_milli=400)
        self.assertGreater(requirement.required_sample_size(), 10)

    def test_paired_design_requires_a_discordant_rate(self):
        with self.assertRaisesRegex(StatisticsError,
                                    "discordant_milli_required"):
            PowerRequirement(design="paired_mcnemar", effect_milli=100)

    def test_unknown_design_is_refused(self):
        with self.assertRaisesRegex(StatisticsError, "design_invalid"):
            PowerRequirement(design="anova", effect_milli=100)

    def test_digest_is_stable_and_binds_the_sample_size(self):
        first = power(effect=400)
        second = power(effect=400)
        self.assertEqual(first.digest(), second.digest())
        self.assertNotEqual(first.digest(), power(effect=300).digest())
        self.assertEqual(first.to_dict()["required_sample_size"],
                         first.required_sample_size())


class PreregistrationTests(unittest.TestCase):
    def setUp(self):
        self.seed, self.public = signatures.generate_keypair()
        self.key_id = "timestamp-key-1"
        self.registry = PreregistrationRegistry(
            trusted_timestamp_keys={self.key_id: self.public.hex()})

    def record(self, **overrides):
        fields = dict(
            preregistration_id="pre-1", protocol_digest=PROTOCOL_DIGEST,
            primary_metric="paired solved_delta E vs A", power=power(),
            holdout_lineages=("lin-holdout",),
            training_lineages=("lin-train",),
            registered_at=REGISTERED_AT,
            timestamp_authority="tsa.example", signer_key_id=self.key_id)
        fields.update(overrides)
        return sign_preregistration(self.seed, **fields)

    def test_signed_preregistration_verifies_and_registers(self):
        digest = self.registry.register(self.record())
        self.assertIsNotNone(self.registry.resolve(digest))

    def test_untrusted_timestamp_authority_is_refused(self):
        other = PreregistrationRegistry(trusted_timestamp_keys={})
        with self.assertRaisesRegex(StatisticsError,
                                    "timestamp_authority_untrusted"):
            other.register(self.record())

    def test_tampered_preregistration_is_refused(self):
        record = self.record()
        tampered = type(record)(
            preregistration_id=record.preregistration_id,
            protocol_digest=record.protocol_digest,
            primary_metric=record.primary_metric,
            power=power(effect=900),
            holdout_lineages=record.holdout_lineages,
            training_lineages=record.training_lineages,
            registered_at=record.registered_at,
            timestamp_authority=record.timestamp_authority,
            signer_key_id=record.signer_key_id,
            signature=record.signature)
        with self.assertRaisesRegex(StatisticsError,
                                    "preregistration_signature_invalid"):
            self.registry.register(tampered)

    def test_resolution_by_protocol_digest(self):
        self.registry.register(self.record())
        self.assertIsNotNone(self.registry.resolve(PROTOCOL_DIGEST))


class LineageTests(unittest.TestCase):
    def setUp(self):
        self.lineages = LineageRegistry()
        self.lineages.add(RepositoryLineage(
            registry_id="repo-1", lineage_id="lin-a", family_id="fam-a"))
        self.lineages.add(RepositoryLineage(
            registry_id="repo-2", lineage_id="lin-b", family_id="fam-b"))

    def test_disjoint_lineages_pass(self):
        self.assertEqual(check_lineage_holdout(
            holdout_repositories=("repo-1",),
            training_lineages=("lin-b",), lineages=self.lineages), [])

    def test_shared_lineage_is_a_leak(self):
        self.assertEqual(check_lineage_holdout(
            holdout_repositories=("repo-1",),
            training_lineages=("lin-a",), lineages=self.lineages),
            ["repo-1"])

    def test_unknown_repository_cannot_be_shown_disjoint(self):
        self.assertEqual(check_lineage_holdout(
            holdout_repositories=("repo-unknown",),
            training_lineages=(), lineages=self.lineages),
            ["repo-unknown"])

    def test_a_repository_cannot_belong_to_two_lineages(self):
        with self.assertRaisesRegex(StatisticsError, "lineage_conflict"):
            self.lineages.add(RepositoryLineage(
                registry_id="repo-1", lineage_id="lin-c",
                family_id="fam-c"))


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.seed, self.public = signatures.generate_keypair()
        self.registry = PreregistrationRegistry(
            trusted_timestamp_keys={"tsa": self.public.hex()})
        self.record = self.registry.resolve  # placeholder for clarity
        self.lineages = LineageRegistry()
        self.lineages.add(RepositoryLineage(
            registry_id="repo-1", lineage_id="lin-a", family_id="fam-a"))

    def preregistration(self, *, effect=400, registered_at=REGISTERED_AT):
        record = sign_preregistration(
            self.seed, preregistration_id="pre-1",
            protocol_digest=PROTOCOL_DIGEST,
            primary_metric="paired solved_delta E vs A",
            power=power(effect=effect),
            holdout_lineages=("lin-a",), training_lineages=("lin-b",),
            registered_at=registered_at, timestamp_authority="tsa",
            signer_key_id="tsa")
        self.registry.register(record)
        return record

    def test_compliant_result_is_confirmatory(self):
        record = self.preregistration()
        verdict = classify(
            preregistration=record, observed_sample_size=29,
            first_evaluation_at=EVALUATED_AT,
            holdout_repositories=("repo-1",), lineages=self.lineages)
        self.assertEqual(verdict.evidence_class, CONFIRMATORY)
        self.assertTrue(verdict.ok)

    def test_underpowered_result_is_exploratory(self):
        record = self.preregistration(effect=100)
        verdict = classify(
            preregistration=record, observed_sample_size=29,
            first_evaluation_at=EVALUATED_AT,
            holdout_repositories=("repo-1",), lineages=self.lineages)
        self.assertEqual(verdict.evidence_class, EXPLORATORY)
        self.assertIn("underpowered", verdict.reasons)

    def test_missing_preregistration_is_exploratory(self):
        verdict = classify(
            preregistration=None, observed_sample_size=500,
            first_evaluation_at=EVALUATED_AT,
            holdout_repositories=("repo-1",), lineages=self.lineages)
        self.assertEqual(verdict.evidence_class, EXPLORATORY)
        self.assertIn("preregistration_missing", verdict.reasons)

    def test_preregistration_after_the_data_is_exploratory(self):
        record = self.preregistration(registered_at=EVALUATED_AT)
        verdict = classify(
            preregistration=record, observed_sample_size=29,
            first_evaluation_at=EVALUATED_AT,
            holdout_repositories=("repo-1",), lineages=self.lineages)
        self.assertEqual(verdict.evidence_class, EXPLORATORY)
        self.assertIn("preregistration_not_before_evaluation",
                      verdict.reasons)

    def test_lineage_leakage_is_exploratory(self):
        record = sign_preregistration(
            self.seed, preregistration_id="pre-2",
            protocol_digest=PROTOCOL_DIGEST,
            primary_metric="paired solved_delta E vs A", power=power(),
            holdout_lineages=("lin-a",), training_lineages=("lin-a",),
            registered_at=REGISTERED_AT, timestamp_authority="tsa",
            signer_key_id="tsa")
        self.registry.register(record)
        verdict = classify(
            preregistration=record, observed_sample_size=29,
            first_evaluation_at=EVALUATED_AT,
            holdout_repositories=("repo-1",), lineages=self.lineages)
        self.assertEqual(verdict.evidence_class, EXPLORATORY)
        self.assertIn("lineage_leakage", verdict.reasons)

    def test_unknown_holdout_repository_is_exploratory(self):
        record = self.preregistration()
        verdict = classify(
            preregistration=record, observed_sample_size=29,
            first_evaluation_at=EVALUATED_AT,
            holdout_repositories=("repo-unknown",), lineages=self.lineages)
        self.assertEqual(verdict.evidence_class, EXPLORATORY)
        self.assertIn("lineage_leakage", verdict.reasons)


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fixture = CertificateFixture(self.root)
        self.addCleanup(self.fixture.stack.close)
        self.tsa_seed, tsa_public = signatures.generate_keypair()
        self.registry = PreregistrationRegistry(
            trusted_timestamp_keys={"tsa": tsa_public.hex()})
        self.lineages = LineageRegistry()
        self.lineages.add(RepositoryLineage(
            registry_id=REPO_REGISTRY_ID, lineage_id="lin-a",
            family_id="fam-a"))
        self.validator = QualificationValidator(
            self.fixture.policy,
            certificate_authority=self.fixture.cert_authority,
            delivery_authority=self.fixture.delivery_authority,
            protocol_registry=self.fixture.protocols,
            receipt_resolver=self.fixture.stack.resolve_receipt,
            delivery_resolver=self.fixture.deliveries.__getitem__,
            preregistrations=self.registry,
            lineages=self.lineages,
            snapshot_resolver=lambda snapshot: REPO_REGISTRY_ID,
        )

    def preregister(self, *, effect=400, registered_at=REGISTERED_AT,
                    training=("lin-b",)):
        record = sign_preregistration(
            self.tsa_seed, preregistration_id="pre-1",
            protocol_digest=PROTOCOL_DIGEST,
            primary_metric=self.fixture.protocol["primary_metric"],
            power=power(effect=effect),
            holdout_lineages=("lin-a",), training_lineages=training,
            registered_at=registered_at, timestamp_authority="tsa",
            signer_key_id="tsa")
        self.registry.register(record)
        return record

    def test_compliant_certificate_is_accepted(self):
        self.preregister(effect=400)
        certificate = self.fixture.certificate()
        validation = self.validator.validate(
            certificate, self.fixture.candidate)
        self.assertTrue(validation.ok, validation.failures)
        self.assertTrue(validation.checks["preregistration_registered"])
        self.assertTrue(
            validation.checks["sample_count_meets_preregistered_power"])

    def test_underpowered_confirmatory_certificate_is_rejected(self):
        self.preregister(effect=100)  # requires > 29 tasks
        certificate = self.fixture.certificate()
        validation = self.validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("sample_count_meets_preregistered_power",
                      validation.failures)
        self.assertTrue(any(d.startswith("underpowered:")
                            for d in validation.details))

    def test_missing_preregistration_is_rejected(self):
        certificate = self.fixture.certificate()
        validation = self.validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("preregistration_registered", validation.failures)

    def test_late_preregistration_is_rejected(self):
        self.preregister(registered_at=EVALUATED_AT)
        certificate = self.fixture.certificate()
        validation = self.validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("preregistration_precedes_evaluation",
                      validation.failures)

    def test_lineage_leakage_is_rejected(self):
        self.preregister(training=("lin-a",))
        certificate = self.fixture.certificate()
        validation = self.validator.validate(
            certificate, self.fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("lineage_holdout", validation.failures)
        self.assertTrue(any(d.startswith("lineage_leakage:")
                            for d in validation.details))


class ReportTests(unittest.TestCase):
    def report(self, tasks):
        return {
            "per_task": [
                {"task_id": task, "arms": {"A": {"valid_solve": False},
                                           "E": {"valid_solve": True}}}
                for task in tasks
            ],
            "governed": {"metrics": {}, "conformance": {"conforms": True}},
        }

    def protocol(self, *, effect=400):
        return {
            "protocol_digest": PROTOCOL_DIGEST,
            "primary_metric": "paired solved_delta E vs A",
            "alpha": 0.05,
            "sample_size": 29,
            "power_requirement": power(effect=effect).to_dict(),
        }

    def test_report_uses_the_declared_power_requirement(self):
        report = analyze_report(
            self.report([f"t{i}" for i in range(29)]),
            protocol=self.protocol(effect=400), real_agent=True,
            hidden_holdout=True)
        self.assertEqual(report["evidence_class"], CONFIRMATORY)
        self.assertIsNotNone(report["power_requirement"])
        self.assertFalse(report["underpowered"])

    def test_underpowered_report_is_exploratory(self):
        report = analyze_report(
            self.report([f"t{i}" for i in range(29)]),
            protocol=self.protocol(effect=100), real_agent=True,
            hidden_holdout=True)
        self.assertEqual(report["evidence_class"], EXPLORATORY)
        self.assertTrue(report["underpowered"])
        self.assertEqual(
            report["release_gate"], "IMPLEMENTED_NOT_EFFICACY_QUALIFIED")


if __name__ == "__main__":
    unittest.main()
