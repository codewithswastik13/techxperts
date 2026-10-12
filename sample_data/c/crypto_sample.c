#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "crypto_sample.h"

int initialize_rsa_context(void) {
    BIGNUM *bne = BN_new();
    RSA *r = RSA_new();
    BN_set_word(bne, RSA_F4);
    // Classical RSA key generation
    int status = RSA_generate_key_ex(r, 2048, bne, NULL);
    RSA_free(r);
    BN_free(bne);
    return status;
}

int setup_ecc_context(void) {
    // OpenSSL EC key allocation by curve name
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL) return 0;
    EC_KEY_free(key);
    return 1;
}

int execute_ecdh_agreement(void) {
    unsigned char secret[32];
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *peer_pub = EC_KEY_get0_public_key(key);
    // Perform ECDH key computation
    int len = ECDH_compute_key(secret, sizeof(secret), peer_pub, key, NULL);
    EC_KEY_free(key);
    return len;
}

int sign_with_ecdsa(const unsigned char *data, size_t len) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    unsigned char dgst[32];
    SHA256(data, len, dgst);
    // ECDSA sign operation
    ECDSA_SIG *sig = ECDSA_do_sign(dgst, sizeof(dgst), key);
    if (sig == NULL) {
        EC_KEY_free(key);
        return 0;
    }
    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    return 1;
}

int encrypt_with_aes(const unsigned char *input, size_t len) {
    AES_KEY aes_key;
    unsigned char user_key[16] = "0123456789abcdef";
    unsigned char out[16];
    // Setup AES encryption key and encrypt single block
    AES_set_encrypt_key(user_key, 128, &aes_key);
    AES_encrypt(input, out, &aes_key);
    return 0;
}

int hash_with_sha256(const unsigned char *data, size_t len) {
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // OpenSSL SHA256 digest computation
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);
    return 0;
}
