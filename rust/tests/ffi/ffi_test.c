/**
 * Test for the Miscreant C ABI
 */

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "miscreant.h"

void test_aead_aes128siv() {
    // AES-SIV Nonce-based Authenticated Encryption Example #1
    const uint8_t key[] = "\x7F\x7E\x7D\x7C\x7B\x7A\x79\x78\x77\x76\x75\x74\x73\x72\x71\x70\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F";
    const uint8_t nonce[] = "\x09\xF9\x11\x02\x9D\x74\xE3\x5B\xD8\x41\x56\xC5\x63\x56\x88\xC0";
    const uint8_t ad[] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\xDE\xAD\xDA\xDA\xDE\xAD\xDA\xDA\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";
    const uint8_t pt[] = "\x74\x68\x69\x73\x20\x69\x73\x20\x73\x6F\x6D\x65\x20\x70\x6C\x61\x69\x6E\x74\x65\x78\x74\x20\x74\x6F\x20\x65\x6E\x63\x72\x79\x70\x74\x20\x75\x73\x69\x6E\x67\x20\x53\x49\x56\x2D\x41\x45\x53";
    const uint8_t ct[] = "\x85\x82\x5E\x22\xE9\x0C\xF2\xDD\xDA\x2C\x54\x8D\xC7\xC1\xB6\x31\x0D\xCD\xAC\xA0\xCE\xBF\x9D\xC6\xCB\x90\x58\x3F\x5B\xF1\x50\x6E\x02\xCD\x48\x83\x2B\x00\xE4\xE5\x98\xB2\xB2\x2A\x53\xE6\x19\x9D\x4D\xF0\xC1\x66\x6A\x35\xA0\x43\x3B\x25\x0D\xC1\x34\xD7\x76";

    uint8_t buf[sizeof(ct)] = {0};
    uint64_t buflen = sizeof(buf) - 1;

    assert(sizeof(pt) + crypto_aead_aes128siv_ABYTES == sizeof(buf));

    // Test encryption
    if(crypto_aead_aes128siv_encrypt(
        buf, &buflen,
        pt, sizeof(pt) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes128siv AEAD: encryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, ct, sizeof(ct) - 1) == 0);

    // Test decryption
    if(crypto_aead_aes128siv_decrypt(
        buf, &buflen,
        ct, sizeof(ct) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes128siv AEAD: decryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, pt, sizeof(pt) - 1) == 0);
}

void test_aead_aes256siv() {
    // AES-SIV Nonce-based Authenticated Encryption Example #2
    const uint8_t key[] = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0\x6F\x6E\x6D\x6C\x6B\x6A\x69\x68\x67\x66\x65\x64\x63\x62\x61\x60\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    const uint8_t nonce[] = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27";
    const uint8_t ad[] = "";
    const uint8_t pt[] = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE";
    const uint8_t ct[] = "\xE6\x18\xD2\xD6\xA8\x6B\x50\xA8\xD7\xDF\x82\xAB\x34\xAA\x95\x0A\xB3\x19\xD7\xFC\x15\xF7\xCD\x1E\xA9\x9B\x1A\x03\x3F\x20";

    uint8_t buf[sizeof(ct)] = {0};
    uint64_t buflen = sizeof(buf) - 1;

    assert(sizeof(pt) + crypto_aead_aes256siv_ABYTES == sizeof(buf));

    // Test encryption
    if(crypto_aead_aes256siv_encrypt(
        buf, &buflen,
        pt, sizeof(pt) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes256siv AEAD: encryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, ct, sizeof(ct) - 1) == 0);

    // Test decryption
    if(crypto_aead_aes256siv_decrypt(
        buf, &buflen,
        ct, sizeof(ct) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes256siv AEAD: decryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, pt, sizeof(pt) - 1) == 0);
}

void test_aead_aes128pmacsiv() {
    // AES-PMAC-SIV Authenticted Encryption with Associated Data Example
    const uint8_t key[] = "\x7F\x7E\x7D\x7C\x7B\x7A\x79\x78\x77\x76\x75\x74\x73\x72\x71\x70\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F";
    const uint8_t nonce[] = "\x09\xF9\x11\x02\x9D\x74\xE3\x5B\xD8\x41\x56\xC5\x63\x56\x88\xC0";
    const uint8_t ad[] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\xDE\xAD\xDA\xDA\xDE\xAD\xDA\xDA\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";
    const uint8_t pt[] = "\x74\x68\x69\x73\x20\x69\x73\x20\x73\x6F\x6D\x65\x20\x70\x6C\x61\x69\x6E\x74\x65\x78\x74\x20\x74\x6F\x20\x65\x6E\x63\x72\x79\x70\x74\x20\x75\x73\x69\x6E\x67\x20\x53\x49\x56\x2D\x41\x45\x53";
    const uint8_t ct[] = "\x14\x63\xD1\x11\x9B\x2A\x27\x97\x24\x1B\xB1\x67\x46\x33\xDF\xF1\x3B\x9D\xE1\x1E\x5E\x2F\x52\x60\x48\xB3\x6C\x40\xC7\x72\x26\x67\xB2\x95\x70\x18\x02\x3B\xF0\xE5\x27\x92\xB7\x03\xA0\x1E\x88\xAA\xCD\x49\x89\x8C\xEC\xFC\xE9\x43\xD7\xF6\x1A\x23\x37\xA0\x97";

    uint8_t buf[sizeof(ct)] = {0};
    uint64_t buflen = sizeof(buf) - 1;

    assert(sizeof(pt) + crypto_aead_aes128pmacsiv_ABYTES == sizeof(buf));

    // Test encryption
    if(crypto_aead_aes128pmacsiv_encrypt(
        buf, &buflen,
        pt, sizeof(pt) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes128pmacsiv AEAD: encryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, ct, sizeof(ct) - 1) == 0);

    // Test decryption
    if(crypto_aead_aes128pmacsiv_decrypt(
        buf, &buflen,
        ct, sizeof(ct) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes128pmacsiv AEAD: decryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, pt, sizeof(pt) - 1) == 0);
}

void test_aead_aes256pmacsiv() {
    // AES-256-PMAC-SIV Authenticted Encryption with Associated Data Example #2
    const uint8_t key[] = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0\x6F\x6E\x6D\x6C\x6B\x6A\x69\x68\x67\x66\x65\x64\x63\x62\x61\x60\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    const uint8_t nonce[] = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27";
    const uint8_t ad[] = "";
    const uint8_t pt[] = "\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE";
    const uint8_t ct[] = "\x06\x23\xA7\x27\x5A\xFD\x50\x82\x03\x5E\x43\xB0\xDC\xAF\xE3\xA8\x91\xC2\xB8\xEE\xD2\xB1\xA0\x7F\x0D\xD2\x51\x80\xE0\x72";

    uint8_t buf[sizeof(ct)] = {0};
    uint64_t buflen = sizeof(buf) - 1;

    assert(sizeof(pt) + crypto_aead_aes256pmacsiv_ABYTES == sizeof(buf));

    // Test encryption
    if(crypto_aead_aes256pmacsiv_encrypt(
        buf, &buflen,
        pt, sizeof(pt) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes256pmacsiv AEAD: encryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, ct, sizeof(ct) - 1) == 0);

    // Test decryption
    if(crypto_aead_aes256pmacsiv_decrypt(
        buf, &buflen,
        ct, sizeof(ct) - 1,
        nonce, sizeof(nonce) - 1,
        ad, sizeof(ad) - 1,
        key
     ) != 0) {
        fputs("error: aes256pmacsiv AEAD: decryption failure\n", stderr);
        abort();
    }

    assert(memcmp(buf, pt, sizeof(pt) - 1) == 0);
}

int main(int argc, char **argv) {
    test_aead_aes128siv();
    test_aead_aes256siv();
    test_aead_aes128pmacsiv();
    test_aead_aes256pmacsiv();

    printf("%s: success\n", argv[0]);
    return 0;
}
