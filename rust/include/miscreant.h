/**
 * Miscreant: Advanced symmetric encryption library which provides the AES-SIV,
 * AES-PMAC-SIV, and STREAM constructions.
 *
 * This header file describes the C ABI exposed from the Rust implementation.
 * C99 support is assumed.
 */

#include <stdint.h>

/********************
 * AES-128-SIV AEAD *
 ********************/

// AES-128-SIV key size
extern uint32_t crypto_aead_aes128siv_KEYBYTES;

// AES-128-SIV authenticator tag size
extern uint32_t crypto_aead_aes128siv_ABYTES;

// AES-128-SIV authenticated encryption
// Requires *ctlen_p == msglen + 16
int crypto_aead_aes128siv_encrypt(
    uint8_t *ct, uint64_t *ctlen_p,
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);

// AES-128-SIV authenticated decryption
// Requires *msglen_p == ctlen
int crypto_aead_aes128siv_decrypt(
    uint8_t *msg, uint64_t *ctlen_p,
    const uint8_t *ct, uint64_t ctlen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);

/********************
 * AES-256-SIV AEAD *
 ********************/

// AES-256-SIV key size
extern uint32_t crypto_aead_aes256siv_KEYBYTES;

// AES-256-SIV authenticator tag size
extern uint32_t crypto_aead_aes256siv_ABYTES;

// AES-256-SIV authenticated encryption
// Requires *ctlen_p == msglen + 16
int crypto_aead_aes256siv_encrypt(
    uint8_t *ct, uint64_t *ctlen_p,
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);

// AES-256-SIV authenticated decryption
// Requires *msglen_p == ctlen
int crypto_aead_aes256siv_decrypt(
    uint8_t *msg, uint64_t *ctlen_p,
    const uint8_t *ct, uint64_t ctlen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);

/*************************
 * AES-128-PMAC-SIV AEAD *
 *************************/

// AES-128-PMAC-SIV key size
extern uint32_t crypto_aead_aes128pmacsiv_KEYBYTES;

// AES-128-PMAC-SIV authenticator tag size
extern uint32_t crypto_aead_aes128pmacsiv_ABYTES;

// AES-128-SIV authenticated encryption
// Requires *ctlen_p == msglen + 16
int crypto_aead_aes128pmacsiv_encrypt(
    uint8_t *ct, uint64_t *ctlen_p,
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);

// AES-128-SIV authenticated decryption
// Requires *msglen_p == ctlen
int crypto_aead_aes128pmacsiv_decrypt(
    uint8_t *msg, uint64_t *ctlen_p,
    const uint8_t *ct, uint64_t ctlen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);

/*************************
 * AES-256-PMAC-SIV AEAD *
 *************************/

// AES-256-PMAC-SIV key size
extern uint32_t crypto_aead_aes256pmacsiv_KEYBYTES;

// AES-256-PMAC-SIV authenticator tag size
extern uint32_t crypto_aead_aes256pmacsiv_ABYTES;

// AES-256-PMAC-SIV authenticated encryption
// Requires *ctlen_p == msglen + 16
int crypto_aead_aes256pmacsiv_encrypt(
    uint8_t *ct, uint64_t *ctlen_p,
    const uint8_t *msg, uint64_t msglen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);

// AES-256-PMAC-SIV authenticated decryption
// Requires *msglen_p == ctlen
int crypto_aead_aes256pmacsiv_decrypt(
    uint8_t *msg, uint64_t *ctlen_p,
    const uint8_t *ct, uint64_t ctlen,
    const uint8_t *nonce, uint64_t noncelen,
    const uint8_t *ad, uint64_t adlen,
    const uint8_t *key
);
