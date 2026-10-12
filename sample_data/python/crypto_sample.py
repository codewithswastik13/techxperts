"""Synthetic Python cryptographic sample for QuantumShield scanner testing.

Contains realistic usage patterns for:
- RSA (cryptography)
- ECC (cryptography)
- ECDH (cryptography)
- ECDSA (cryptography)
- AES (cryptography)
- SHA-256 (hashlib)
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_rsa_keypair():
    # Generate classical RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key


def generate_ecc_keypair():
    # Generate NIST P-256 ECC key
    curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve)
    return private_key


def perform_ecdh_key_exchange(private_key, peer_public_key):
    # Perform ECDH key agreement
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key


def sign_data_ecdsa(private_key, data: bytes):
    # Perform ECDSA signature
    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    return signature


def encrypt_aes(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # Perform AES encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def compute_sha256(data: bytes) -> str:
    # Compute SHA-256 digest
    digest = hashlib.sha256(data).hexdigest()
    return digest
