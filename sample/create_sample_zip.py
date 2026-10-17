"""
create_sample_zip.py — Generates the bundled sample repository ZIP for QuantumShield demo.

Usage:
  python sample/create_sample_zip.py

Output:
  sample/sample_repo.zip

This script is safe to re-run and produces a deterministic output.
The sample files contain ONLY deliberately selected cryptographic patterns,
no real credentials or private keys.
"""

import io
import os
import zipfile

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "sample_repo.zip")
FRONTEND_PUBLIC_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "frontend", "public", "sample_repo.zip"
)

# ---------------------------------------------------------------------------
# Sample files — realistic cryptographic usage patterns
# ---------------------------------------------------------------------------

SAMPLE_FILES: dict[str, str] = {
    # --- Python: RSA sign and encrypt (HIGH risk, two distinct purposes) ---
    "python_app/auth/token_signer.py": '''"""
JWT-like token signing using RSA.
Expected detections: RSA (digital signature purpose)
Expected risk: HIGH — quantum-vulnerable public-key operation
"""
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256


class TokenSigner:
    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def sign_token(self, payload: bytes) -> bytes:
        h = SHA256.new(payload)
        signer = pss.new(self.private_key)
        return signer.sign(h)

    def verify_token(self, payload: bytes, signature: bytes) -> bool:
        h = SHA256.new(payload)
        verifier = pss.new(self.public_key)
        try:
            verifier.verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
''',

    # --- Python: RSA OAEP encryption (HIGH risk, key establishment purpose) ---
    "python_app/crypto/session_key.py": '''"""
Symmetric session key exchange using RSA OAEP.
Expected detections: RSA (key establishment purpose)
Expected risk: HIGH — 'Store Now Decrypt Later' threat applies
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def wrap_session_key(session_key: bytes, recipient_public_key_pem: bytes) -> bytes:
    """Encrypt a session key with the recipient's RSA public key."""
    recipient_key = RSA.import_key(recipient_public_key_pem)
    cipher = PKCS1_OAEP.new(recipient_key)
    return cipher.encrypt(session_key)


def unwrap_session_key(wrapped_key: bytes, private_key_pem: bytes) -> bytes:
    """Decrypt a wrapped session key using our RSA private key."""
    key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(wrapped_key)
''',

    # --- Python: AES-128 (MODERATE risk — should upgrade to AES-256) ---
    "python_app/storage/db_encrypt.py": '''"""
Database field encryption using AES-128-CBC.
Expected detections: AES-128
Expected risk: MODERATE — Grover halves effective security to ~64 bits
Recommendation: upgrade key length to AES-256
"""
from Crypto.Cipher import AES
import os

# 16-byte key = AES-128
KEY_SIZE = 16


def encrypt_field(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt a database field. Returns (ciphertext, iv)."""
    assert len(key) == KEY_SIZE, "AES-128 requires a 16-byte key"
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = _pad(data)
    return cipher.encrypt(padded), iv


def _pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)
''',

    # --- Python: AES-256 (LOWER risk — retain with good mode) ---
    "python_app/storage/vault.py": '''"""
High-security secret vault using AES-256-GCM.
Expected detections: AES-256
Expected risk: LOWER — retains ~128-bit quantum security margin
No PQC replacement needed; mode and IV hygiene still required.
"""
from Crypto.Cipher import AES
import os

KEY_SIZE = 32  # 32 bytes = AES-256


def encrypt_secret(plaintext: bytes, master_key: bytes) -> dict:
    """Encrypt a secret with AES-256-GCM. Returns nonce, tag, and ciphertext."""
    assert len(master_key) == KEY_SIZE
    nonce = os.urandom(16)
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": nonce, "tag": tag, "ciphertext": ciphertext}
''',

    # --- Python: SHA-256 (LOWER risk — hash function, not encryption) ---
    "python_app/utils/checksum.py": '''"""
File integrity verification using SHA-256.
Expected detections: SHA-256
Expected risk: LOWER — hash function, not a public-key or symmetric cipher
Grover provides quadratic speedup but hash functions are not quantum-broken.
"""
import hashlib


def compute_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_checksum(data: bytes, expected: str) -> bool:
    return compute_checksum(data) == expected
''',

    # --- Java: ECDSA (HIGH risk — digital signature) ---
    "java_app/src/auth/Signer.java": '''/**
 * Digital signature using ECDSA with P-256 curve.
 * Expected detections: ECDSA
 * Expected risk: HIGH — elliptic curve discrete log broken by Shor's algorithm
 * Recommendation: migrate to ML-DSA (NIST FIPS 204)
 */
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class Signer {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public Signer() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = kpg.generateKeyPair();
        this.privateKey = kp.getPrivate();
        this.publicKey = kp.getPublic();
    }

    public byte[] sign(byte[] data) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    public boolean verify(byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}
''',

    # --- Java: RSA key exchange (HIGH risk) ---
    "java_app/src/crypto/KeyExchange.java": '''/**
 * RSA-based session key establishment.
 * Expected detections: RSA
 * Expected risk: HIGH — RSA factorization broken by Shor's algorithm
 * Recommendation: migrate to ML-KEM (NIST FIPS 203)
 */
import javax.crypto.Cipher;
import java.security.*;

public class KeyExchange {

    public byte[] wrapKey(byte[] sessionKey, PublicKey recipientKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, recipientKey);
        return cipher.doFinal(sessionKey);
    }

    public byte[] unwrapKey(byte[] wrappedKey, PrivateKey myKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, myKey);
        return cipher.doFinal(wrappedKey);
    }

    public KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
''',

    # --- C: RSA/ECDH via OpenSSL (HIGH risk) ---
    "c_app/network/handshake.c": '''/*
 * TLS-like handshake using ECDH for key agreement.
 * Expected detections: ECDH
 * Expected risk: HIGH — ECDH vulnerable to Shor's algorithm CRQC attack
 * Recommendation: hybrid X25519+ML-KEM during transition
 */
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <string.h>

int ecdh_derive_shared_secret(EVP_PKEY *local_key, EVP_PKEY *peer_key,
                               unsigned char *secret, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(local_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) goto cleanup;
    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) goto cleanup;

    EVP_PKEY_CTX_free(ctx);
    return 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return -1;
}
''',

    # --- Negative case: safe utility code (should not trigger) ---
    "python_app/utils/string_utils.py": '''"""
String utility functions — no cryptographic operations.
Expected detections: NONE
This file is a negative test case.
"""

def slugify(text: str) -> str:
    """Convert a string to a URL-safe slug."""
    return text.lower().replace(" ", "-").strip("-")


def truncate(text: str, max_length: int = 100) -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."
''',

    # --- Documentation ---
    "README.md": """# QuantumShield Sample Repository

This is a bundled sample repository for QuantumShield demonstration purposes.

## Purpose
Provides repeatable, safe test input for the QuantumShield scanner and risk engine.

## Expected Detections

| File | Algorithm | Expected Risk |
|---|---|---|
| python_app/auth/token_signer.py | RSA | HIGH — digital signature |
| python_app/crypto/session_key.py | RSA | HIGH — key establishment |
| python_app/storage/db_encrypt.py | AES-128 | MODERATE |
| python_app/storage/vault.py | AES-256 | LOWER |
| python_app/utils/checksum.py | SHA-256 | LOWER |
| java_app/src/auth/Signer.java | ECDSA | HIGH — digital signature |
| java_app/src/crypto/KeyExchange.java | RSA | HIGH — key establishment |
| c_app/network/handshake.c | ECDH | HIGH — key agreement |
| python_app/utils/string_utils.py | — | None (negative case) |

## Disclaimer
No real credentials or private keys are included.
All cryptographic patterns are illustrative; no code in this sample is meant to be executed.
""",
}


def create_sample_zip(output_path: str) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in SAMPLE_FILES.items():
            zf.writestr(name, content.encode("utf-8") if isinstance(content, str) else content)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(buf.getvalue())

    print(f"Sample ZIP created: {output_path}")
    print(f"Entries: {len(SAMPLE_FILES)}")


if __name__ == "__main__":
    create_sample_zip(OUTPUT_PATH)
    if os.path.isdir(os.path.dirname(FRONTEND_PUBLIC_PATH)):
        create_sample_zip(FRONTEND_PUBLIC_PATH)
