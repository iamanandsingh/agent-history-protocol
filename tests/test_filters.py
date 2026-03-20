"""Tests for PII filter presets (pci, pii-us, pii-eu, credentials, hipaa)."""

from __future__ import annotations

import unittest

from ahp.core.filters import PCRE2, PRESETS, FilterPipeline


class TestAllPIIPresets(unittest.TestCase):
    """Verify all 5 spec-required PII presets exist and work."""

    def test_all_presets_exist(self):
        required = ["pci", "pii-us", "pii-eu", "credentials", "hipaa"]
        for name in required:
            self.assertIn(name, PRESETS, f"Missing preset: {name}")

    def test_pci_credit_card(self):
        pipeline = FilterPipeline(presets=["pci"])
        filtered, redacted = pipeline.apply(b"Card: 4111 1111 1111 1111", "parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:CC]", filtered)

    def test_pii_us_ssn(self):
        pipeline = FilterPipeline(presets=["pii-us"])
        filtered, redacted = pipeline.apply(b"SSN: 123-45-6789", "parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:SSN]", filtered)

    def test_pii_eu_iban(self):
        pipeline = FilterPipeline(presets=["pii-eu"])
        filtered, redacted = pipeline.apply(b"IBAN: GB29NWBK60161331926819", "parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:IBAN]", filtered)

    def test_credentials_bearer(self):
        pipeline = FilterPipeline(presets=["credentials"])
        filtered, redacted = pipeline.apply(b"Authorization: Bearer sk-abc123def456ghi789", "parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:TOKEN]", filtered)

    def test_hipaa_mrn(self):
        pipeline = FilterPipeline(presets=["hipaa"])
        filtered, redacted = pipeline.apply(b"MRN: 1234567890", "parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:MRN]", filtered)

    def test_hipaa_email(self):
        pipeline = FilterPipeline(presets=["hipaa"])
        filtered, redacted = pipeline.apply(b"Contact: patient@hospital.com", "parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:EMAIL]", filtered)

    def test_hipaa_phone(self):
        pipeline = FilterPipeline(presets=["hipaa"])
        filtered, redacted = pipeline.apply(b"Phone: (555) 123-4567", "parameters")
        self.assertTrue(redacted)
        self.assertIn(b"[REDACTED:PHONE]", filtered)

    def test_all_presets_combined(self):
        """Apply all presets simultaneously — nothing should crash."""
        pipeline = FilterPipeline(presets=["pci", "pii-us", "pii-eu", "credentials", "hipaa"])
        text = (
            b"Card: 4111 1111 1111 1111, "
            b"SSN: 123-45-6789, "
            b"IBAN: DE89370400440532013000, "
            b"Bearer sk-secret123456789012, "
            b"MRN: 9876543210"
        )
        filtered, redacted = pipeline.apply(text, "parameters")
        self.assertTrue(redacted)
        self.assertNotIn(b"4111", filtered)
        self.assertNotIn(b"123-45-6789", filtered)

    def test_pcre2_flag(self):
        """Report whether PCRE2 is available (informational only)."""
        print(f"\n  PCRE2 available: {PCRE2}")


if __name__ == "__main__":
    unittest.main()
