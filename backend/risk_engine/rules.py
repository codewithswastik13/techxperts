"""
rules.py - Cryptographic and Quantum Risk Assessment Rules

Contains documented constants, threat models, classification rules,
and Post-Quantum Cryptography (PQC) migration recommendations.
Standards referenced:
- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
- NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA)
"""

from typing import Dict, Any


# Standardized Output Categories
class RiskLevel:
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOWER = "LOWER"
    UNKNOWN = "UNKNOWN"


class MigrationPriority:
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class CryptographicPurpose:
    KEY_ESTABLISHMENT = "KEY_ESTABLISHMENT"
    DIGITAL_SIGNATURE = "DIGITAL_SIGNATURE"
    SYMMETRIC_ENCRYPTION = "SYMMETRIC_ENCRYPTION"
    HASH_FUNCTION = "HASH_FUNCTION"
    UNKNOWN = "UNKNOWN"
    AMBIGUOUS = "AMBIGUOUS"


# Rule Definitions
# Each rule provides risk classification, technical explanation,
# purpose-specific recommendations, and manual review requirements.
RULES: Dict[str, Dict[str, Any]] = {
    "RSA": {
        "risk_level": RiskLevel.HIGH,
        "default_priority": MigrationPriority.HIGH,
        "explanation": (
            "RSA-based public-key cryptography relies on the integer factorization problem, "
            "which is broken in polynomial time by Shor's algorithm on a cryptanalytically "
            "relevant quantum computer (CRQC)."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.DIGITAL_SIGNATURE: {
                "recommendation": (
                    "Migrate RSA signature generation and verification to NIST FIPS 204 ML-DSA "
                    "(e.g., ML-DSA-65). For stateful firmware or secure boot scenarios, consider "
                    "LMS or XMSS (RFC 8554 / RFC 8391)."
                ),
                "migration_priority": MigrationPriority.HIGH,
                "manual_review_required": False,
            },
            CryptographicPurpose.KEY_ESTABLISHMENT: {
                "recommendation": (
                    "Migrate RSA key transport or encryption to a post-quantum key encapsulation "
                    "mechanism, specifically NIST FIPS 203 ML-KEM (e.g., ML-KEM-768), or an approved "
                    "hybrid classical-quantum key exchange."
                ),
                "migration_priority": MigrationPriority.HIGH,
                "manual_review_required": False,
            },
            CryptographicPurpose.UNKNOWN: {
                "recommendation": (
                    "Confirmed RSA public-key usage detected, but the specific operation (digital "
                    "signature, key exchange, or data encryption) cannot be unambiguously determined "
                    "from the pattern. Review the call site: consider ML-DSA for signatures or ML-KEM "
                    "for key establishment."
                ),
                "migration_priority": MigrationPriority.REVIEW_REQUIRED,
                "manual_review_required": True,
            },
        },
    },
    "ECDSA": {
        "risk_level": RiskLevel.HIGH,
        "default_priority": MigrationPriority.HIGH,
        "default_purpose": CryptographicPurpose.DIGITAL_SIGNATURE,
        "explanation": (
            "ECDSA (Elliptic Curve Digital Signature Algorithm) relies on the discrete logarithm "
            "problem over elliptic curves, which is completely broken by Shor's algorithm on a CRQC."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.DIGITAL_SIGNATURE: {
                "recommendation": (
                    "Migrate digital signatures to NIST FIPS 204 ML-DSA (e.g., ML-DSA-44 or ML-DSA-65). "
                    "For applications requiring compact public keys or stateful signing, evaluate "
                    "SLH-DSA (FIPS 205) or stateful hash-based signatures (LMS/XMSS)."
                ),
                "migration_priority": MigrationPriority.HIGH,
                "manual_review_required": False,
            },
        },
    },
    "ECDH": {
        "risk_level": RiskLevel.HIGH,
        "default_priority": MigrationPriority.HIGH,
        "default_purpose": CryptographicPurpose.KEY_ESTABLISHMENT,
        "explanation": (
            "ECDH (Elliptic Curve Diffie-Hellman) key agreement is vulnerable to Shor's algorithm, "
            "allowing a future CRQC to recover shared secrets from recorded network traffic "
            "('Store Now, Decrypt Later' attack)."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.KEY_ESTABLISHMENT: {
                "recommendation": (
                    "Migrate key exchange to NIST FIPS 203 ML-KEM (e.g., ML-KEM-768). During transition, "
                    "deploy a hybrid key exchange combining X25519/ECDH with ML-KEM to preserve classical "
                    "security guarantees."
                ),
                "migration_priority": MigrationPriority.HIGH,
                "manual_review_required": False,
            },
        },
    },
    "ECC_GENERIC": {
        "risk_level": RiskLevel.HIGH,
        "default_priority": MigrationPriority.REVIEW_REQUIRED,
        "default_purpose": CryptographicPurpose.UNKNOWN,
        "explanation": (
            "Elliptic Curve Cryptography (ECC) public-key operations rely on the elliptic curve discrete "
            "logarithm problem, which is broken by Shor's algorithm on a CRQC."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.UNKNOWN: {
                "recommendation": (
                    "Generic elliptic curve usage identified. Inspect the code to determine whether "
                    "the curve is used for key exchange (e.g., ECDH) or digital signatures (e.g., ECDSA). "
                    "Plan migration to ML-KEM for key exchange or ML-DSA for signatures."
                ),
                "migration_priority": MigrationPriority.REVIEW_REQUIRED,
                "manual_review_required": True,
            },
        },
    },
    "AES-128": {
        "risk_level": RiskLevel.MODERATE,
        "default_priority": MigrationPriority.MEDIUM,
        "default_purpose": CryptographicPurpose.SYMMETRIC_ENCRYPTION,
        "explanation": (
            "AES-128 is a symmetric block cipher. Quantum attacks using Grover's algorithm provide a quadratic "
            "speedup for unstructured search, halving the theoretical security margin to ~64 bits. While Grover's "
            "attack requires high quantum depth, 64-bit work factor does not meet long-term post-quantum security margins."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.SYMMETRIC_ENCRYPTION: {
                "recommendation": (
                    "Upgrade symmetric key length to AES-256 to restore 128-bit quantum security margin under "
                    "Grover's algorithm. Do not replace symmetric ciphers with asymmetric post-quantum algorithms."
                ),
                "migration_priority": MigrationPriority.MEDIUM,
                "manual_review_required": False,
            },
        },
    },
    "AES-256": {
        "risk_level": RiskLevel.LOWER,
        "default_priority": MigrationPriority.LOW,
        "default_purpose": CryptographicPurpose.SYMMETRIC_ENCRYPTION,
        "explanation": (
            "AES-256 provides a robust quantum security margin against Grover's algorithm, retaining ~128 bits "
            "of theoretical security margin. It is classified as quantum-resistant for symmetric encryption."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.SYMMETRIC_ENCRYPTION: {
                "recommendation": (
                    "Retain AES-256. Ensure an authenticated cipher mode (e.g., AES-GCM or AES-GCM-SIV) is used, "
                    "with cryptographically secure initialization vectors (IVs) and proper key management. "
                    "No PQC replacement is required."
                ),
                "migration_priority": MigrationPriority.LOW,
                "manual_review_required": False,
            },
        },
    },
    "SHA-256": {
        "risk_level": RiskLevel.LOWER,
        "default_priority": MigrationPriority.LOW,
        "default_purpose": CryptographicPurpose.HASH_FUNCTION,
        "explanation": (
            "SHA-256 is a cryptographic hash function, not an encryption or public-key algorithm. Grover's algorithm "
            "reduces preimage resistance to ~128 bits, which remains secure. Collision resistance is affected by "
            "quantum algorithms (BHT), but physical memory constraints keep SHA-256 viable against near-term quantum threats."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.HASH_FUNCTION: {
                "recommendation": (
                    "Retain SHA-256 for general hashing and HMAC usage. For applications requiring extreme longevity "
                    "or NIST Security Level 5 margin, consider SHA-384, SHA-512, or SHA3-256/512. Cryptographic hash "
                    "functions do not use public-key mechanisms."
                ),
                "migration_priority": MigrationPriority.LOW,
                "manual_review_required": False,
            },
        },
    },
    "UNKNOWN": {
        "risk_level": RiskLevel.UNKNOWN,
        "default_priority": MigrationPriority.REVIEW_REQUIRED,
        "default_purpose": CryptographicPurpose.UNKNOWN,
        "explanation": (
            "The detected algorithm or pattern could not be recognized with high confidence by the rule engine, "
            "or insufficient cryptographic metadata was provided."
        ),
        "purpose_recommendations": {
            CryptographicPurpose.UNKNOWN: {
                "recommendation": (
                    "Perform manual cryptographic code review. Inspect the source file, variable names, and matched "
                    "pattern to identify the exact cryptographic primitive, key size, and operational mode."
                ),
                "migration_priority": MigrationPriority.REVIEW_REQUIRED,
                "manual_review_required": True,
            },
        },
    },
}
