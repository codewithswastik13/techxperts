#ifndef QUANTUMSHIELD_CRYPTO_SAMPLE_H
#define QUANTUMSHIELD_CRYPTO_SAMPLE_H

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

int initialize_rsa_context(void);
int setup_ecc_context(void);
int execute_ecdh_agreement(void);
int sign_with_ecdsa(const unsigned char *data, size_t len);
int encrypt_with_aes(const unsigned char *input, size_t len);
int hash_with_sha256(const unsigned char *data, size_t len);

#endif /* QUANTUMSHIELD_CRYPTO_SAMPLE_H */
