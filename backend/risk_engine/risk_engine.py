"""
risk_engine.py - Core Risk Engine and Post-Quantum Migration Intelligence

Provides deterministic, rule-based classification and migration recommendations
for cryptographic findings detected in source code repositories.
"""

import re
from typing import Any, Dict, List, Optional
from .rules import (
    RiskLevel,
    MigrationPriority,
    CryptographicPurpose,
    RULES,
)


def _safe_str(val: Any) -> str:
    """Helper to convert any input safely to a stripped string."""
    if val is None:
        return ""
    return str(val).strip()


def normalize_algorithm(algo_raw: str, pattern: str = "", evidence: str = "") -> str:
    """
    Normalizes raw algorithm strings and context into standard rule keys.
    Prevents false positives on accidental substrings.
    """
    raw = _safe_str(algo_raw).upper()
    ctx = f"{raw} {_safe_str(pattern).upper()} {_safe_str(evidence).upper()}"

    # 1. RSA
    # Match RSA as a discrete token or clear prefix (e.g. RSA-2048, RSA_PKCS1, RSA/ECB)
    if re.search(r"\bRSA\b", raw) or re.search(r"^RSA[-_0-9]", raw):
        return "RSA"

    # 2. Elliptic Curve Schemes
    if re.search(r"\bECDSA\b", ctx):
        return "ECDSA"
    if re.search(r"\bECDH\b", ctx) or "DIFFIE-HELLMAN" in ctx or "X25519" in ctx:
        return "ECDH"
    # Generic ECC: check for explicit ECC, Elliptic Curve, or curve identifiers
    if (
        re.search(r"\bECC\b", raw)
        or "ELLIPTIC" in raw
        or re.search(r"\b(SECP256R1|SECP384R1|SECP521R1|ED25519)\b", ctx)
        or (raw == "EC" and ("CURVE" in ctx or "KEY" in ctx or "SIGN" in ctx))
    ):
        return "ECC_GENERIC"

    # 3. Symmetric Ciphers - AES
    if "AES" in raw or "AES" in ctx:
        if "128" in raw or "128" in ctx:
            return "AES-128"
        if "256" in raw or "256" in ctx:
            return "AES-256"
        # If AES is mentioned without specific key size, treat conservatively
        if re.search(r"\bAES\b", raw):
            return "AES-128"

    # 4. Hash Functions - SHA-256
    if re.search(r"\bSHA[-_]?256\b", raw):
        return "SHA-256"

    # 5. Check context fallback for RSA
    if re.search(r"\bRSA\b", ctx):
        return "RSA"

    return "UNKNOWN"


def infer_cryptographic_purpose(
    algo_key: str,
    matched_pattern: str = "",
    evidence: str = "",
    explicit_purpose: Optional[str] = None,
) -> str:
    """
    Infers the likely cryptographic purpose based on the algorithm key,
    pattern evidence, and any explicit metadata.
    """
    # If the finding already has a valid explicit purpose, normalize it
    if explicit_purpose:
        norm_exp = _safe_str(explicit_purpose).upper()
        if norm_exp in [
            CryptographicPurpose.DIGITAL_SIGNATURE,
            CryptographicPurpose.KEY_ESTABLISHMENT,
            CryptographicPurpose.SYMMETRIC_ENCRYPTION,
            CryptographicPurpose.HASH_FUNCTION,
        ]:
            return norm_exp

    # Purpose inherently fixed by algorithm identity
    if algo_key == "ECDSA":
        return CryptographicPurpose.DIGITAL_SIGNATURE
    if algo_key == "ECDH":
        return CryptographicPurpose.KEY_ESTABLISHMENT
    if algo_key in ("AES-128", "AES-256"):
        return CryptographicPurpose.SYMMETRIC_ENCRYPTION
    if algo_key == "SHA-256":
        return CryptographicPurpose.HASH_FUNCTION

    # Search pattern and evidence for functional indicators
    text = f"{_safe_str(matched_pattern).lower()} {_safe_str(evidence).lower()}"

    sig_indicators = ["sign", "verify", "signature", "pss", "pkcs1v15_sign"]
    key_indicators = [
        "encrypt",
        "decrypt",
        "cipher",
        "oaep",
        "exchange",
        "key_transport",
        "agreement",
        "kem",
        "secret",
        "wrap",
    ]

    has_sig = any(ind in text for ind in sig_indicators)
    has_key = any(ind in text for ind in key_indicators)

    if has_sig and has_key:
        return CryptographicPurpose.AMBIGUOUS
    if has_sig:
        return CryptographicPurpose.DIGITAL_SIGNATURE
    if has_key:
        return CryptographicPurpose.KEY_ESTABLISHMENT

    return CryptographicPurpose.UNKNOWN


def analyze_single_finding(finding: Any) -> Dict[str, Any]:
    """
    Processes and enriches a single cryptographic finding with quantum risk
    assessment and post-quantum migration intelligence.
    Preserves all original fields from the scanner.
    """
    # Guard against non-dict entries
    if not isinstance(finding, dict):
        return {
            "error": "Malformed finding: expected dictionary",
            "raw_input": str(finding),
            "risk_level": RiskLevel.UNKNOWN,
            "explanation": "Invalid finding format; item could not be processed.",
            "cryptographic_purpose": CryptographicPurpose.UNKNOWN,
            "recommendation": "Review scanner output formatting.",
            "migration_priority": MigrationPriority.REVIEW_REQUIRED,
            "manual_review_required": True,
        }

    # Clone original finding to preserve all scanner fields intact
    enriched: Dict[str, Any] = dict(finding)

    raw_algo = _safe_str(finding.get("algorithm"))
    pattern = _safe_str(finding.get("matched_pattern"))
    evidence = _safe_str(finding.get("evidence"))
    explicit_purpose = finding.get("cryptographic_purpose") or finding.get("purpose")

    # 1. Normalize algorithm to recognized rule key
    algo_key = normalize_algorithm(raw_algo, pattern, evidence)

    # 2. Infer cryptographic purpose
    purpose = infer_cryptographic_purpose(algo_key, pattern, evidence, explicit_purpose)

    # 3. Apply classification rules
    rule = RULES.get(algo_key, RULES["UNKNOWN"])
    risk_level = rule.get("risk_level", RiskLevel.UNKNOWN)
    explanation = rule.get("explanation", "")

    # 4. Resolve purpose-specific migration recommendations
    purpose_recs = rule.get("purpose_recommendations", {})

    if purpose in purpose_recs:
        rec_data = purpose_recs[purpose]
        recommendation = rec_data.get("recommendation", "")
        migration_priority = rec_data.get("migration_priority", rule.get("default_priority"))
        manual_review = rec_data.get("manual_review_required", False)
    elif CryptographicPurpose.UNKNOWN in purpose_recs:
        rec_data = purpose_recs[CryptographicPurpose.UNKNOWN]
        recommendation = rec_data.get("recommendation", "")
        migration_priority = rec_data.get("migration_priority", rule.get("default_priority"))
        manual_review = rec_data.get("manual_review_required", True)
    else:
        recommendation = (
            "Evaluate cryptographic requirements and determine specific post-quantum migration path."
        )
        migration_priority = rule.get("default_priority", MigrationPriority.REVIEW_REQUIRED)
        manual_review = True

    # Ambiguous purpose cases (e.g. pattern has both sign and encrypt words) require manual review
    if purpose == CryptographicPurpose.AMBIGUOUS:
        manual_review = True
        migration_priority = MigrationPriority.REVIEW_REQUIRED
        recommendation = (
            "Conflicting cryptographic usage indicators detected (both signing and encryption/key exchange). "
            "Manual review required to identify specific call site before selecting ML-DSA or ML-KEM."
        )

    # If algorithm was unknown, force manual review and review priority
    if algo_key == "UNKNOWN":
        risk_level = RiskLevel.UNKNOWN
        migration_priority = MigrationPriority.REVIEW_REQUIRED
        manual_review = True

    # Set enriched output fields
    enriched["risk_level"] = risk_level
    enriched["explanation"] = explanation
    enriched["cryptographic_purpose"] = purpose
    enriched["recommendation"] = recommendation
    enriched["migration_priority"] = migration_priority
    enriched["manual_review_required"] = manual_review

    return enriched


def analyze_findings(findings: Any) -> List[Dict[str, Any]]:
    """
    Public entry point for Member 2's Risk Engine.

    Consumes a list of scanner findings and produces enriched findings
    containing quantum risk classifications and PQC migration recommendations.

    Args:
        findings: List of finding dictionaries from Member 1's scanner.

    Returns:
        List of enriched dictionaries with preserved metadata and risk fields.
    """
    if findings is None:
        return []

    if not isinstance(findings, list):
        # Gracefully handle single finding passed instead of list
        if isinstance(findings, dict):
            return [analyze_single_finding(findings)]
        return []

    return [analyze_single_finding(f) for f in findings]
