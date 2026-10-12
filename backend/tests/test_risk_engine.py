"""
test_risk_engine.py - Comprehensive Unit Tests for QuantumShield Risk Engine
"""

import os
import sys
import json
import unittest

# Ensure the root directory and backend directory are in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.risk_engine import (
    analyze_findings,
    RiskLevel,
    MigrationPriority,
    CryptographicPurpose,
)


class TestRiskEngine(unittest.TestCase):
    """Test suite covering quantum risk classification and PQC migration intelligence."""

    def test_rsa_key_establishment_context(self):
        """RSA used for key exchange or encryption should recommend ML-KEM."""
        findings = [
            {
                "file_path": "src/crypto/session.py",
                "line_number": 42,
                "language": "python",
                "algorithm": "RSA-2048",
                "matched_pattern": "RSA OAEP encryption cipher",
                "evidence": "cipher = PKCS1_OAEP.new(recipient_key); cipher.encrypt(session_key)",
            }
        ]
        results = analyze_findings(findings)
        self.assertEqual(len(results), 1)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.KEY_ESTABLISHMENT)
        self.assertIn("ML-KEM", res["recommendation"])
        self.assertNotIn("ML-DSA", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.HIGH)
        self.assertFalse(res["manual_review_required"])

    def test_rsa_digital_signature_context(self):
        """RSA used for signatures should recommend ML-DSA."""
        findings = [
            {
                "file_path": "src/auth/tokens.py",
                "line_number": 105,
                "language": "python",
                "algorithm": "RSA",
                "matched_pattern": "RSA PSS signature verification",
                "evidence": "verifier = pss.new(rsa_key); verifier.verify(digest, sig)",
            }
        ]
        results = analyze_findings(findings)
        self.assertEqual(len(results), 1)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.DIGITAL_SIGNATURE)
        self.assertIn("ML-DSA", res["recommendation"])
        self.assertNotIn("ML-KEM", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.HIGH)
        self.assertFalse(res["manual_review_required"])

    def test_rsa_unknown_purpose(self):
        """RSA without clear operational evidence should have unknown purpose and flag manual review."""
        findings = [
            {
                "file_path": "src/keys/generator.py",
                "line_number": 12,
                "language": "python",
                "algorithm": "RSA",
                "matched_pattern": "RSA key generation",
                "evidence": "key = RSA.generate(2048)",
            }
        ]
        results = analyze_findings(findings)
        self.assertEqual(len(results), 1)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.UNKNOWN)
        # Should provide conditional guidance mentioning both
        self.assertIn("ML-DSA", res["recommendation"])
        self.assertIn("ML-KEM", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.REVIEW_REQUIRED)
        self.assertTrue(res["manual_review_required"])

    def test_ecdh_key_establishment(self):
        """ECDH must be classified as HIGH risk, KEY_ESTABLISHMENT purpose, and recommend ML-KEM."""
        findings = [
            {
                "file_path": "network/handshake.c",
                "line_number": 88,
                "language": "c",
                "algorithm": "ECDH",
                "matched_pattern": "ECDH shared secret agreement",
                "evidence": "EVP_PKEY_derive(ctx, secret, &secret_len);",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.KEY_ESTABLISHMENT)
        self.assertIn("ML-KEM", res["recommendation"])
        self.assertNotIn("ML-DSA", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.HIGH)
        self.assertFalse(res["manual_review_required"])

    def test_ecdsa_digital_signatures(self):
        """ECDSA must be classified as HIGH risk, DIGITAL_SIGNATURE purpose, and recommend ML-DSA."""
        findings = [
            {
                "file_path": "src/crypto/signer.java",
                "line_number": 64,
                "language": "java",
                "algorithm": "ECDSA",
                "matched_pattern": "Signature.getInstance('SHA256withECDSA')",
                "evidence": "Signature sig = Signature.getInstance('SHA256withECDSA'); sig.initSign(privKey);",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.DIGITAL_SIGNATURE)
        self.assertIn("ML-DSA", res["recommendation"])
        self.assertNotIn("ML-KEM", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.HIGH)
        self.assertFalse(res["manual_review_required"])

    def test_aes_128_classification(self):
        """AES-128 should be MODERATE risk and recommend upgrading to AES-256, NOT ML-KEM or ML-DSA."""
        findings = [
            {
                "file_path": "storage/db_encrypt.py",
                "line_number": 33,
                "language": "python",
                "algorithm": "AES-128",
                "matched_pattern": "AES 128-bit CBC mode",
                "evidence": "cipher = AES.new(key, AES.MODE_CBC, iv)",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.MODERATE)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.SYMMETRIC_ENCRYPTION)
        self.assertIn("AES-256", res["recommendation"])
        self.assertNotIn("ML-KEM", res["recommendation"])
        self.assertNotIn("ML-DSA", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.MEDIUM)
        self.assertFalse(res["manual_review_required"])

    def test_aes_256_classification(self):
        """AES-256 provides sufficient Grover quantum security margin and requires no PQC replacement."""
        findings = [
            {
                "file_path": "storage/vault.py",
                "line_number": 50,
                "language": "python",
                "algorithm": "AES-256",
                "matched_pattern": "AES-GCM 256-bit",
                "evidence": "cipher = AES.new(master_key, AES.MODE_GCM)",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.LOWER)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.SYMMETRIC_ENCRYPTION)
        self.assertEqual(res["migration_priority"], MigrationPriority.LOW)
        self.assertNotIn("ML-KEM", res["recommendation"])
        self.assertNotIn("ML-DSA", res["recommendation"])
        self.assertFalse(res["manual_review_required"])

    def test_sha_256_classification(self):
        """SHA-256 is a hash function, not encryption; LOWER risk and does not recommend ML-KEM/DSA."""
        findings = [
            {
                "file_path": "utils/checksum.py",
                "line_number": 15,
                "language": "python",
                "algorithm": "SHA-256",
                "matched_pattern": "hashlib.sha256() call",
                "evidence": "digest = hashlib.sha256(data).hexdigest()",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.LOWER)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.HASH_FUNCTION)
        self.assertNotIn("encryption", res["explanation"].lower().split("hash function")[0])
        self.assertNotIn("ML-KEM", res["recommendation"])
        self.assertNotIn("ML-DSA", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.LOW)
        self.assertFalse(res["manual_review_required"])

    def test_unknown_algorithm(self):
        """Unrecognized algorithm names must be flagged UNKNOWN with manual review required."""
        findings = [
            {
                "file_path": "legacy/custom_cipher.py",
                "line_number": 99,
                "language": "python",
                "algorithm": "SuperCipher-X9",
                "matched_pattern": "custom block scramble",
                "evidence": "scramble_blocks(data)",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]

        self.assertEqual(res["risk_level"], RiskLevel.UNKNOWN)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.UNKNOWN)
        self.assertEqual(res["migration_priority"], MigrationPriority.REVIEW_REQUIRED)
        self.assertTrue(res["manual_review_required"])

    def test_empty_input(self):
        """Empty input must safely return an empty list without exceptions."""
        self.assertEqual(analyze_findings([]), [])
        self.assertEqual(analyze_findings(None), [])

    def test_missing_optional_fields(self):
        """Findings with missing optional fields should not crash."""
        findings = [
            {"algorithm": "RSA"},
            {"algorithm": "AES-256"},
        ]
        results = analyze_findings(findings)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["risk_level"], RiskLevel.HIGH)
        self.assertEqual(results[1]["risk_level"], RiskLevel.LOWER)

    def test_malformed_finding_objects(self):
        """Malformed elements in findings list should be handled gracefully."""
        findings = ["not_a_dict", 12345, None]
        results = analyze_findings(findings)
        self.assertEqual(len(results), 3)
        for res in results:
            self.assertEqual(res["risk_level"], RiskLevel.UNKNOWN)
            self.assertTrue(res["manual_review_required"])

    def test_multiple_findings_preservation(self):
        """Original file_path, line_number, and evidence must be preserved across multiple findings."""
        findings = [
            {"file_path": "a.py", "line_number": 10, "algorithm": "RSA", "evidence": "sign(msg)"},
            {"file_path": "b.py", "line_number": 20, "algorithm": "ECDH", "evidence": "derive()"},
            {"file_path": "c.py", "line_number": 30, "algorithm": "AES-128", "evidence": "encrypt()"},
        ]
        results = analyze_findings(findings)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["file_path"], "a.py")
        self.assertEqual(results[0]["line_number"], 10)
        self.assertEqual(results[1]["file_path"], "b.py")
        self.assertEqual(results[1]["line_number"], 20)
        self.assertEqual(results[2]["file_path"], "c.py")
        self.assertEqual(results[2]["line_number"], 30)

    def test_json_serializability(self):
        """Enriched findings must be completely JSON-serializable for FastAPI and frontend integration."""
        findings = [
            {
                "file_path": "src/main.py",
                "line_number": 1,
                "language": "python",
                "algorithm": "ECDSA",
                "matched_pattern": "sign",
                "evidence": "ecdsa.sign()",
            }
        ]
        results = analyze_findings(findings)
        serialized = json.dumps(results)
        self.assertIsInstance(serialized, str)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized[0]["algorithm"], "ECDSA")
        self.assertEqual(deserialized[0]["risk_level"], RiskLevel.HIGH)

    def test_deterministic_output(self):
        """Identical inputs must yield identical outputs."""
        finding = {
            "file_path": "crypto.py",
            "line_number": 10,
            "algorithm": "RSA-4096",
            "matched_pattern": "decrypt",
            "evidence": "rsa.decrypt(data)",
        }
        res1 = analyze_findings([finding])
        res2 = analyze_findings([finding])
        self.assertEqual(res1, res2)

    def test_ambiguous_cryptographic_purpose(self):
        """Findings containing contradictory purpose clues must be marked AMBIGUOUS with review required."""
        findings = [
            {
                "file_path": "crypto/hybrid.py",
                "line_number": 55,
                "algorithm": "RSA",
                "matched_pattern": "RSA sign and encrypt helper",
                "evidence": "def sign_and_encrypt(data): rsa.sign(data); rsa.encrypt(data)",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.AMBIGUOUS)
        self.assertEqual(res["migration_priority"], MigrationPriority.REVIEW_REQUIRED)
        self.assertTrue(res["manual_review_required"])

    def test_generic_ecc_unknown_purpose(self):
        """Generic ECC without purpose evidence should be HIGH risk and flag manual review."""
        findings = [
            {
                "file_path": "crypto/curves.py",
                "line_number": 19,
                "algorithm": "ECC",
                "matched_pattern": "elliptic curve generation",
                "evidence": "curve = get_curve('secp256r1')",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]
        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.UNKNOWN)
        self.assertEqual(res["migration_priority"], MigrationPriority.REVIEW_REQUIRED)
        self.assertTrue(res["manual_review_required"])

    def test_generic_ecc_signing_purpose(self):
        """Generic ECC with signing evidence should infer DIGITAL_SIGNATURE and recommend ML-DSA."""
        findings = [
            {
                "file_path": "auth/ecc_auth.py",
                "line_number": 40,
                "algorithm": "secp256r1",
                "matched_pattern": "curve signature verification",
                "evidence": "verify_signature(pubkey, message, sig)",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]
        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.DIGITAL_SIGNATURE)
        self.assertIn("ML-DSA", res["recommendation"])
        self.assertNotIn("ML-KEM", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.HIGH)
        self.assertFalse(res["manual_review_required"])

    def test_generic_ecc_key_exchange_purpose(self):
        """Generic ECC with key agreement evidence should infer KEY_ESTABLISHMENT and recommend ML-KEM."""
        findings = [
            {
                "file_path": "network/ecc_key.py",
                "line_number": 75,
                "algorithm": "ECC",
                "matched_pattern": "elliptic curve key agreement",
                "evidence": "shared_secret = compute_secret(peer_key)",
            }
        ]
        results = analyze_findings(findings)
        res = results[0]
        self.assertEqual(res["risk_level"], RiskLevel.HIGH)
        self.assertEqual(res["cryptographic_purpose"], CryptographicPurpose.KEY_ESTABLISHMENT)
        self.assertIn("ML-KEM", res["recommendation"])
        self.assertNotIn("ML-DSA", res["recommendation"])
        self.assertEqual(res["migration_priority"], MigrationPriority.HIGH)
        self.assertFalse(res["manual_review_required"])


if __name__ == "__main__":
    unittest.main()
