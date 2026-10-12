"""Synthetic non-cryptographic Python sample for false-positive validation.

This file intentionally references cryptographic terms in comments and docstrings
to ensure the scanner does not produce false positives from non-code text.
"""

# Note: Architecture team evaluated RSA and AES-GCM for this module,
# but chose to delegate authentication to an external OAuth gateway.


def calculate_statistics(numbers: list[float]) -> dict:
    """Calculate mean and variance. Do not confuse with SHA-256 or ECC."""
    if not numbers:
        return {"mean": 0.0, "total": 0.0}

    total = sum(numbers)
    mean = total / len(numbers)
    return {"mean": mean, "total": total}


def format_user_greeting(username: str) -> str:
    # Comments mentioning ECDH and ECDSA should never generate findings
    sanitized = username.strip().title()
    return f"Welcome, {sanitized}!"
