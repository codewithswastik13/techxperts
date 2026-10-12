#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Legacy Reference Notes:
 * This code does not perform cryptography directly.
 * Historically, RSA_generate_key_ex, AES_encrypt, and SHA256_Init
 * were considered here, but replaced with TLS socket communication.
 */

int calculate_fibonacci(int n) {
    // Single line comment: do not trigger on ECDSA_sign or ECDH_compute_key
    if (n <= 1) return n;
    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}

int main(void) {
    int val = calculate_fibonacci(10);
    printf("Fibonacci result: %d\n", val);
    return 0;
}
