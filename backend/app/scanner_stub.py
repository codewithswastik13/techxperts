"""
QuantumShield — scanner_stub.py

Explicit test double for Member 1's scanner.
This module is used ONLY when the real scanner is unavailable at import time.
It is never presented to users or judges as genuine scanning output.

When Member 1 delivers backend/scanner/__init__.py exposing scan_repository(),
the import in main.py will resolve to the real implementation automatically.
Remove or ignore this file after the real scanner is integrated.
"""


def scan_repository(path: str) -> list:
    """
    Stub implementation — returns an empty list.
    Ensures the API remains functional for integration development
    and test-double-based testing while the real scanner is pending.
    """
    return []
