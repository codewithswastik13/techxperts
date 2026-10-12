"""QuantumShield Scanner - Cryptographic Detection Rules.

Defines language-specific regular expression rules for detecting classical
and asymmetric cryptographic algorithm usage across Python, Java, and C.

Supported Algorithms:
- RSA
- ECC
- ECDH
- ECDSA
- AES
- SHA-256
"""

from dataclasses import dataclass
import re
from typing import Dict, List


@dataclass(frozen=True)
class DetectionRule:
    """Represents a single static detection pattern."""
    algorithm: str
    matched_pattern: str
    pattern: re.Pattern


# Mapping from normalized file extension to supported language identifier
EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".c": "c",
    ".h": "c",
}

# Detection rules cataloged by language identifier
RULES: Dict[str, List[DetectionRule]] = {
    "python": [
        # RSA
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA private key generation (cryptography)",
            pattern=re.compile(r"\brsa\.generate_private_key\s*\("),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA asymmetric primitive import",
            pattern=re.compile(r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+[^#\n]*\brsa\b"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA padding scheme (OAEP/PKCS1v15)",
            pattern=re.compile(r"\bpadding\.(?:OAEP|PKCS1v15)\b"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA key generation (PyCryptodome)",
            pattern=re.compile(r"\bRSA\.generate\s*\("),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA key import (PyCryptodome)",
            pattern=re.compile(r"\bRSA\.import_key\s*\("),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA key module import (Crypto.PublicKey)",
            pattern=re.compile(r"from\s+Crypto\.PublicKey\s+import\s+[^#\n]*\bRSA\b"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA key generation (python-rsa)",
            pattern=re.compile(r"\brsa\.newkeys\s*\("),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA cryptographic operation (python-rsa)",
            pattern=re.compile(r"\brsa\.(?:encrypt|decrypt|sign|verify)\s*\("),
        ),

        # ECC
        DetectionRule(
            algorithm="ECC",
            matched_pattern="ECC private key generation (cryptography)",
            pattern=re.compile(r"\bec\.generate_private_key\s*\("),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="Elliptic curve curve selection",
            pattern=re.compile(r"\bec\.(?:SECP\d+[rRkK]\d*|BrainpoolP\w+|Prime\w+)\s*\(\s*\)"),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="ECC asymmetric primitive import",
            pattern=re.compile(r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+[^#\n]*\bec\b"),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="ECC key generation (PyCryptodome)",
            pattern=re.compile(r"\bECC\.generate\s*\("),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="ECC key module import (Crypto.PublicKey)",
            pattern=re.compile(r"from\s+Crypto\.PublicKey\s+import\s+[^#\n]*\bECC\b"),
        ),

        # ECDH
        DetectionRule(
            algorithm="ECDH",
            matched_pattern="ECDH key agreement primitive (cryptography)",
            pattern=re.compile(r"\bec\.ECDH\s*\(\s*\)"),
        ),
        DetectionRule(
            algorithm="ECDH",
            matched_pattern="ECDH key exchange call",
            pattern=re.compile(r"\.exchange\s*\(\s*ec\.ECDH\s*\(\s*\)"),
        ),
        DetectionRule(
            algorithm="ECDH",
            matched_pattern="ECDH primitive import",
            pattern=re.compile(r"from\s+cryptography\.hazmat\.primitives\.asymmetric\.ec\s+import\s+[^#\n]*\bECDH\b"),
        ),

        # ECDSA
        DetectionRule(
            algorithm="ECDSA",
            matched_pattern="ECDSA signature algorithm primitive",
            pattern=re.compile(r"\bec\.ECDSA\s*\("),
        ),
        DetectionRule(
            algorithm="ECDSA",
            matched_pattern="ECDSA primitive import",
            pattern=re.compile(r"from\s+cryptography\.hazmat\.primitives\.asymmetric\.ec\s+import\s+[^#\n]*\bECDSA\b"),
        ),
        DetectionRule(
            algorithm="ECDSA",
            matched_pattern="ECDSA DSS signature scheme (PyCryptodome)",
            pattern=re.compile(r"\bdss\.new\s*\([^)]*['\"]fips-186-3['\"]"),
        ),

        # AES
        DetectionRule(
            algorithm="AES",
            matched_pattern="AES cipher algorithm initialization (cryptography)",
            pattern=re.compile(r"\balgorithms\.AES\s*\("),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="AES cipher algorithm import",
            pattern=re.compile(r"from\s+cryptography\.hazmat\.primitives\.ciphers\.algorithms\s+import\s+[^#\n]*\bAES\b"),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="AES cipher instantiation (PyCryptodome)",
            pattern=re.compile(r"\bAES\.new\s*\("),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="AES cipher import (Crypto.Cipher)",
            pattern=re.compile(r"from\s+Crypto\.Cipher\s+import\s+[^#\n]*\bAES\b"),
        ),

        # SHA-256
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="SHA-256 digest creation (hashlib)",
            pattern=re.compile(r"\bhashlib\.sha256\s*\("),
        ),
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="SHA-256 hash primitive (cryptography)",
            pattern=re.compile(r"\bhashes\.SHA256\s*\(\s*\)"),
        ),
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="SHA-256 hash instantiation (PyCryptodome)",
            pattern=re.compile(r"\bSHA256\.new\s*\("),
        ),
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="SHA-256 hash import (Crypto.Hash)",
            pattern=re.compile(r"from\s+Crypto\.Hash\s+import\s+[^#\n]*\bSHA256\b"),
        ),
    ],

    "java": [
        # RSA
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA KeyPairGenerator initialization",
            pattern=re.compile(r"KeyPairGenerator\.getInstance\s*\(\s*[\"']RSA[\"']"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA KeyFactory initialization",
            pattern=re.compile(r"KeyFactory\.getInstance\s*\(\s*[\"']RSA[\"']"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA Cipher transformation",
            pattern=re.compile(r"Cipher\.getInstance\s*\(\s*[\"']RSA(?:/[^\"']*)?[\"']"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA Signature algorithm",
            pattern=re.compile(r"Signature\.getInstance\s*\(\s*[\"'](?:SHA\d+|MD5)withRSA[\"']"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="RSA key interface reference",
            pattern=re.compile(r"(?:import\s+java\.security\.interfaces\.(?:RSAPrivateKey|RSAPublicKey|RSAPrivateCrtKey)|(?:RSAPrivateKey|RSAPublicKey|RSAPrivateCrtKey)\s+[A-Za-z_]\w*|\((?:RSAPrivateKey|RSAPublicKey|RSAPrivateCrtKey)\))"),
        ),

        # ECC
        DetectionRule(
            algorithm="ECC",
            matched_pattern="EC KeyPairGenerator initialization",
            pattern=re.compile(r"KeyPairGenerator\.getInstance\s*\(\s*[\"']EC[\"']"),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="EC KeyFactory initialization",
            pattern=re.compile(r"KeyFactory\.getInstance\s*\(\s*[\"']EC[\"']"),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="EC curve parameter specification",
            pattern=re.compile(r"new\s+ECGenParameterSpec\s*\("),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="EC key or parameter interface reference",
            pattern=re.compile(r"(?:import\s+java\.security\.(?:spec\.)?(?:ECPublicKey|ECPrivateKey|ECParameterSpec)|(?:ECPublicKey|ECPrivateKey|ECParameterSpec)\s+[A-Za-z_]\w*|\((?:ECPublicKey|ECPrivateKey|ECParameterSpec)\))"),
        ),

        # ECDH
        DetectionRule(
            algorithm="ECDH",
            matched_pattern="ECDH KeyAgreement initialization",
            pattern=re.compile(r"KeyAgreement\.getInstance\s*\(\s*[\"']ECDH(?:C)?[\"']"),
        ),

        # ECDSA
        DetectionRule(
            algorithm="ECDSA",
            matched_pattern="ECDSA Signature algorithm",
            pattern=re.compile(r"Signature\.getInstance\s*\(\s*[\"'](?:SHA\d+|NONE)withECDSA[\"']"),
        ),

        # AES
        DetectionRule(
            algorithm="AES",
            matched_pattern="AES Cipher transformation",
            pattern=re.compile(r"Cipher\.getInstance\s*\(\s*[\"']AES(?:/[^\"']*)?[\"']"),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="AES KeyGenerator initialization",
            pattern=re.compile(r"KeyGenerator\.getInstance\s*\(\s*[\"']AES[\"']"),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="AES SecretKeySpec construction",
            pattern=re.compile(r"new\s+SecretKeySpec\s*\([^,]+,\s*[\"']AES[\"']\s*\)"),
        ),

        # SHA-256
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="SHA-256 MessageDigest initialization",
            pattern=re.compile(r"MessageDigest\.getInstance\s*\(\s*[\"']SHA-?256[\"']"),
        ),
    ],

    "c": [
        # RSA
        DetectionRule(
            algorithm="RSA",
            matched_pattern="OpenSSL RSA header inclusion",
            pattern=re.compile(r"#\s*include\s*<openssl/rsa\.h>"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="OpenSSL RSA key generation",
            pattern=re.compile(r"\bRSA_generate_key_ex\s*\("),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="OpenSSL RSA context allocation",
            pattern=re.compile(r"\bRSA_new\s*\("),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="OpenSSL RSA encryption/decryption",
            pattern=re.compile(r"\bRSA_public_encrypt\s*\(|\bRSA_private_decrypt\s*\("),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="OpenSSL RSA context initialization",
            pattern=re.compile(r"\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA\b"),
        ),
        DetectionRule(
            algorithm="RSA",
            matched_pattern="OpenSSL EVP_PKEY_RSA identifier",
            pattern=re.compile(r"(?<![\"'])\bEVP_PKEY_RSA\b(?![\"'])"),
        ),

        # ECC
        DetectionRule(
            algorithm="ECC",
            matched_pattern="OpenSSL EC header inclusion",
            pattern=re.compile(r"#\s*include\s*<openssl/ec\.h>"),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="OpenSSL EC key allocation",
            pattern=re.compile(r"\bEC_KEY_new(?:_by_curve_name)?\s*\("),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="OpenSSL EC curve group allocation",
            pattern=re.compile(r"\bEC_GROUP_new_by_curve_name\s*\("),
        ),
        DetectionRule(
            algorithm="ECC",
            matched_pattern="OpenSSL EVP_PKEY_EC identifier",
            pattern=re.compile(r"(?<![\"'])\bEVP_PKEY_EC\b(?![\"'])"),
        ),

        # ECDH
        DetectionRule(
            algorithm="ECDH",
            matched_pattern="OpenSSL ECDH header inclusion",
            pattern=re.compile(r"#\s*include\s*<openssl/ecdh\.h>"),
        ),
        DetectionRule(
            algorithm="ECDH",
            matched_pattern="OpenSSL ECDH key computation",
            pattern=re.compile(r"\bECDH_compute_key\s*\("),
        ),
        DetectionRule(
            algorithm="ECDH",
            matched_pattern="OpenSSL EVP key derivation (ECDH)",
            pattern=re.compile(r"\bEVP_PKEY_derive_init\s*\("),
        ),

        # ECDSA
        DetectionRule(
            algorithm="ECDSA",
            matched_pattern="OpenSSL ECDSA header inclusion",
            pattern=re.compile(r"#\s*include\s*<openssl/ecdsa\.h>"),
        ),
        DetectionRule(
            algorithm="ECDSA",
            matched_pattern="OpenSSL ECDSA sign/verify",
            pattern=re.compile(r"\bECDSA_do_sign\s*\(|\bECDSA_do_verify\s*\("),
        ),
        DetectionRule(
            algorithm="ECDSA",
            matched_pattern="OpenSSL ECDSA operation",
            pattern=re.compile(r"\bECDSA_sign\s*\(|\bECDSA_verify\s*\("),
        ),

        # AES
        DetectionRule(
            algorithm="AES",
            matched_pattern="OpenSSL AES header inclusion",
            pattern=re.compile(r"#\s*include\s*<openssl/aes\.h>"),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="OpenSSL AES key setup",
            pattern=re.compile(r"\bAES_set_encrypt_key\s*\(|\bAES_set_decrypt_key\s*\("),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="OpenSSL AES cipher call",
            pattern=re.compile(r"\bAES_encrypt\s*\(|\bAES_decrypt\s*\(|\bAES_cbc_encrypt\s*\("),
        ),
        DetectionRule(
            algorithm="AES",
            matched_pattern="OpenSSL EVP AES cipher function",
            pattern=re.compile(r"\bEVP_aes_(?:128|192|256)_(?:cbc|gcm|ctr|ecb)\s*\("),
        ),

        # SHA-256
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="OpenSSL SHA header inclusion",
            pattern=re.compile(r"#\s*include\s*<openssl/sha\.h>"),
        ),
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="OpenSSL SHA256 digest function",
            pattern=re.compile(r"\bSHA256_Init\s*\(|\bSHA256_Update\s*\(|\bSHA256_Final\s*\("),
        ),
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="OpenSSL one-shot SHA256 hash",
            pattern=re.compile(r"\bSHA256\s*\("),
        ),
        DetectionRule(
            algorithm="SHA-256",
            matched_pattern="OpenSSL EVP_sha256 digest function",
            pattern=re.compile(r"\bEVP_sha256\s*\("),
        ),
    ],
}
