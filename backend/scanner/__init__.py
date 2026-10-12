"""QuantumShield Cryptographic Scanner Module.

Exposes the primary public interface `scan_repository`.
"""

from .scanner import scan_repository

__all__ = ["scan_repository"]
