// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

// Ported from Go implementation
//
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// which is based on public domain implementation
// by Vincent Rijmen, Antoon Bosselaers, Paulo Barreto
// (rijndael-alg-fst.c, 3.0, December 2000)

import { BlockCipher } from "@stablelib/blockcipher";
import { wipe } from "@stablelib/wipe";
import { readUint32BE, writeUint32BE } from "@stablelib/binary";

// Powers of x mod poly in GF(2).
const POWX = new Uint8Array([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f
]);

// FIPS-197 Figure 7. S-box substitution values in hexadecimal format.
const SBOX0 = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]);

// FIPS-197 Figure 14.  Inverse S-box substitution values in hexadecimal format.
const SBOX1 = new Uint8Array([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]);

// Encryption and decryption tables.
// Will be computed by initialize() when the first AES instance is created.
let isInitialized = false;
let Te0: Uint32Array, Te1: Uint32Array, Te2: Uint32Array, Te3: Uint32Array;
let Td0: Uint32Array, Td1: Uint32Array, Td2: Uint32Array, Td3: Uint32Array;

// Initialize generates encryption and decryption tables.
function initialize() {
    const poly = (1 << 8) | (1 << 4) | (1 << 3) | (1 << 1) | (1 << 0);

    function mul(b: number, c: number): number {
        let i = b;
        let j = c;
        let s = 0;
        for (let k = 1; k < 0x100 && j !== 0; k <<= 1) {
            // Invariant: k == 1<<n, i == b * x^n
            if ((j & k) !== 0) {
                // s += i in GF(2); xor in binary
                s ^= i;
                j ^= k; // turn off bit to end loop early
            }
            // i *= x in GF(2) modulo the polynomial
            i <<= 1;
            if ((i & 0x100) !== 0) {
                i ^= poly;
            }
        }
        return s;
    }

    const rot = (x: number) => (x << 24) | (x >>> 8);

    // Generate encryption tables.
    Te0 = new Uint32Array(256);
    Te1 = new Uint32Array(256);
    Te2 = new Uint32Array(256);
    Te3 = new Uint32Array(256);

    for (let i = 0; i < 256; i++) {
        const s = SBOX0[i];
        let w = (mul(s, 2) << 24) | (s << 16) | (s << 8) | mul(s, 3);
        Te0[i] = w; w = rot(w);
        Te1[i] = w; w = rot(w);
        Te2[i] = w; w = rot(w);
        Te3[i] = w; w = rot(w);
    }

    // Generate decryption tables.
    Td0 = new Uint32Array(256);
    Td1 = new Uint32Array(256);
    Td2 = new Uint32Array(256);
    Td3 = new Uint32Array(256);

    for (let i = 0; i < 256; i++) {
        const s = SBOX1[i];
        let w = (mul(s, 0xe) << 24) | (mul(s, 0x9) << 16) |
            (mul(s, 0xd) << 8) | mul(s, 0xb);
        Td0[i] = w; w = rot(w);
        Td1[i] = w; w = rot(w);
        Td2[i] = w; w = rot(w);
        Td3[i] = w; w = rot(w);
    }

    isInitialized = true;
}

/**
 * AES block cipher.
 *
 * This implementation uses lookup tables, so it's susceptible to cache-timing
 * side-channel attacks. A constant-time version we tried was super slow (a few
 * kilobytes per second), so we'll have to live with it.
 *
 * Key size: 16, 24 or 32 bytes, block size: 16 bytes.
 */
export class AES implements BlockCipher {
    // AES block size in bytes.
    readonly blockSize = 16;

    // Key byte length.
    private _keyLen: number;

    // Expanded encryption key.
    private _encKey: Uint32Array;

    // Expanded decryption key. May be undefined if instance
    // was created "noDecryption" option set to true.
    private _decKey: Uint32Array | undefined;

    /**
     * Constructs AES with the given 16, 24 or 32-byte key
     * for AES-128, AES-192, or AES-256.
     *
     * If noDecryption is true, decryption key will not expanded,
     * saving time and memory for cipher modes when decryption
     * is not used (such as AES-CTR).
     *
     */
    constructor(key: Uint8Array, noDecryption = false) {
        if (!isInitialized) {
            initialize();
        }
        this._keyLen = key.length;
        this.setKey(key, noDecryption);
    }

    /**
     * Re-initializes this instance with the new key.
     *
     * This is helpful to avoid allocations.
     */
    setKey(key: Uint8Array, noDecryption = false): this {
        if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
            throw new Error("AES: wrong key size (must be 16, 24 or 32)");
        }
        if (this._keyLen !== key.length) {
            throw new Error("AES: initialized with different key size");
        }

        // If we haven't yet, allocate space for expanded keys.
        if (!this._encKey) {
            this._encKey = new Uint32Array(key.length + 28);
        }
        if (noDecryption) {
            // Wipe decryption key, as we no longer need it.
            if (this._decKey) {
                wipe(this._decKey);
            }
        } else {
            if (!this._decKey) {
                this._decKey = new Uint32Array(key.length + 28);
            }
        }
        expandKey(key, this._encKey, this._decKey);
        return this;
    }

    /**
     * Cleans expanded keys from memory, setting them to zeros.
     */
    clean(): this {
        if (this._encKey) {
            wipe(this._encKey);
        }
        if (this._decKey) {
            wipe(this._decKey);
        }
        return this;
    }

    // TODO(dchest): specify if blocks can be the same array.

    /**
     * Encrypt 16-byte block src into 16-byte block dst.
     *
     * This function should not be used to encrypt data without any
     * cipher mode! It should only be used to implement a cipher mode.
     */
    encryptBlock(src: Uint8Array, dst: Uint8Array): this {
        // Check block lengths.
        if (src.length < this.blockSize) {
            throw new Error("AES: source block too small");
        }
        if (dst.length < this.blockSize) {
            throw new Error("AES: destination block too small");
        }

        // Encrypt block.
        encryptBlock(this._encKey, src, dst);

        return this;
    }

    /**
     * Decrypt 16-byte block src into 16-byte block dst.
     *
     * This function should not be used to encrypt data without any
     * cipher mode! It should only be used to implement a cipher mode.
     */
    decryptBlock(src: Uint8Array, dst: Uint8Array): this {
        // Check block lengths.
        if (src.length < this.blockSize) {
            throw new Error("AES: source block too small");
        }
        if (dst.length < this.blockSize) {
            throw new Error("AES: destination block too small");
        }

        // Check that we have decryption key.
        if (!this._decKey) {
            throw new Error("AES: decrypting with instance created with noDecryption option");
        } else {
            decryptBlock(this._decKey, src, dst);
        }

        return this;
    }
}

// Apply sbox0 to each byte in w.
function subw(w: number): number {
    return ((SBOX0[(w >>> 24) & 0xff]) << 24) |
        ((SBOX0[(w >>> 16) & 0xff]) << 16) |
        ((SBOX0[(w >>> 8) & 0xff]) << 8) |
        (SBOX0[w & 0xff]);
}

// Rotate
function rotw(w: number): number {
    return (w << 8) | (w >>> 24);
}

function expandKey(key: Uint8Array, encKey: Uint32Array, decKey?: Uint8Array): void {
    const nk = key.length / 4 | 0;
    const n = encKey.length;
    for (let i = 0; i < nk; i++) {
        encKey[i] = readUint32BE(key, i * 4);
    }
    for (let i = nk; i < n; i++) {
        let t = encKey[i - 1];
        if (i % nk === 0) {
            t = subw(rotw(t)) ^ (POWX[i / nk - 1] << 24);
        } else if (nk > 6 && i % nk === 4) {
            t = subw(t);
        }
        encKey[i] = encKey[i - nk] ^ t;
    }

    if (decKey) {
        // Derive decryption key from encryption key.
        // Reverse the 4-word round key sets from enc to produce dec.
        // All sets but the first and last get the MixColumn transform applied.
        for (let i = 0; i < n; i += 4) {
            const ei = n - i - 4;
            for (let j = 0; j < 4; j++) {
                let x = encKey[ei + j];
                if (i > 0 && i + 4 < n) {
                    x = Td0[SBOX0[(x >>> 24) & 0xff]] ^ Td1[SBOX0[(x >>> 16) & 0xff]] ^
                        Td2[SBOX0[(x >>> 8) & 0xff]] ^ Td3[SBOX0[x & 0xff]];
                }
                decKey[i + j] = x;
            }
        }
    }
}

function encryptBlock(xk: Uint32Array, src: Uint8Array, dst: Uint8Array): void {
    let s0 = readUint32BE(src, 0);
    let s1 = readUint32BE(src, 4);
    let s2 = readUint32BE(src, 8);
    let s3 = readUint32BE(src, 12);

    // First round just XORs input with key.
    s0 ^= xk[0];
    s1 ^= xk[1];
    s2 ^= xk[2];
    s3 ^= xk[3];

    let t0 = 0, t1 = 0, t2 = 0, t3 = 0;

    // Middle rounds shuffle using tables.
    // Number of rounds is set by length of expanded key.
    const nr = xk.length / 4 - 2; // - 2: one above, one more below
    let k = 4;

    for (let r = 0; r < nr; r++) {
        t0 = xk[k + 0] ^ Te0[(s0 >>> 24) & 0xff] ^ Te1[(s1 >>> 16) & 0xff] ^
            Te2[(s2 >>> 8) & 0xff] ^ Te3[s3 & 0xff];

        t1 = xk[k + 1] ^ Te0[(s1 >>> 24) & 0xff] ^ Te1[(s2 >>> 16) & 0xff] ^
            Te2[(s3 >>> 8) & 0xff] ^ Te3[s0 & 0xff];

        t2 = xk[k + 2] ^ Te0[(s2 >>> 24) & 0xff] ^ Te1[(s3 >>> 16) & 0xff] ^
            Te2[(s0 >>> 8) & 0xff] ^ Te3[s1 & 0xff];

        t3 = xk[k + 3] ^ Te0[(s3 >>> 24) & 0xff] ^ Te1[(s0 >>> 16) & 0xff] ^
            Te2[(s1 >>> 8) & 0xff] ^ Te3[s2 & 0xff];

        k += 4;
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    // Last round uses s-box directly and XORs to produce output.
    s0 = (SBOX0[t0 >>> 24] << 24) | (SBOX0[(t1 >>> 16) & 0xff]) << 16 |
        (SBOX0[(t2 >>> 8) & 0xff]) << 8 | (SBOX0[t3 & 0xff]);

    s1 = (SBOX0[t1 >>> 24] << 24) | (SBOX0[(t2 >>> 16) & 0xff]) << 16 |
        (SBOX0[(t3 >>> 8) & 0xff]) << 8 | (SBOX0[t0 & 0xff]);

    s2 = (SBOX0[t2 >>> 24] << 24) | (SBOX0[(t3 >>> 16) & 0xff]) << 16 |
        (SBOX0[(t0 >>> 8) & 0xff]) << 8 | (SBOX0[t1 & 0xff]);

    s3 = (SBOX0[t3 >>> 24] << 24) | (SBOX0[(t0 >>> 16) & 0xff]) << 16 |
        (SBOX0[(t1 >>> 8) & 0xff]) << 8 | (SBOX0[t2 & 0xff]);

    s0 ^= xk[k + 0];
    s1 ^= xk[k + 1];
    s2 ^= xk[k + 2];
    s3 ^= xk[k + 3];

    writeUint32BE(s0, dst, 0);
    writeUint32BE(s1, dst, 4);
    writeUint32BE(s2, dst, 8);
    writeUint32BE(s3, dst, 12);
}

function decryptBlock(xk: Uint32Array, src: Uint8Array, dst: Uint8Array): void {
    let s0 = readUint32BE(src, 0);
    let s1 = readUint32BE(src, 4);
    let s2 = readUint32BE(src, 8);
    let s3 = readUint32BE(src, 12);

    // First round just XORs input with key.
    s0 ^= xk[0];
    s1 ^= xk[1];
    s2 ^= xk[2];
    s3 ^= xk[3];

    let t0 = 0, t1 = 0, t2 = 0, t3 = 0;

    // Middle rounds shuffle using tables.
    // Number of rounds is set by length of expanded key.
    const nr = xk.length / 4 - 2; // - 2: one above, one more below
    let k = 4;

    for (let r = 0; r < nr; r++) {
        t0 = xk[k + 0] ^ Td0[(s0 >>> 24) & 0xff] ^ Td1[(s3 >>> 16) & 0xff] ^
            Td2[(s2 >>> 8) & 0xff] ^ Td3[s1 & 0xff];

        t1 = xk[k + 1] ^ Td0[(s1 >>> 24) & 0xff] ^ Td1[(s0 >>> 16) & 0xff] ^
            Td2[(s3 >>> 8) & 0xff] ^ Td3[s2 & 0xff];

        t2 = xk[k + 2] ^ Td0[(s2 >>> 24) & 0xff] ^ Td1[(s1 >>> 16) & 0xff] ^
            Td2[(s0 >>> 8) & 0xff] ^ Td3[s3 & 0xff];

        t3 = xk[k + 3] ^ Td0[(s3 >>> 24) & 0xff] ^ Td1[(s2 >>> 16) & 0xff] ^
            Td2[(s1 >>> 8) & 0xff] ^ Td3[s0 & 0xff];

        k += 4;
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
    }

    // Last round uses s-box directly and XORs to produce output.
    s0 = (SBOX1[t0 >>> 24] << 24) | (SBOX1[(t3 >>> 16) & 0xff]) << 16 |
        (SBOX1[(t2 >>> 8) & 0xff]) << 8 | (SBOX1[t1 & 0xff]);

    s1 = (SBOX1[t1 >>> 24] << 24) | (SBOX1[(t0 >>> 16) & 0xff]) << 16 |
        (SBOX1[(t3 >>> 8) & 0xff]) << 8 | (SBOX1[t2 & 0xff]);

    s2 = (SBOX1[t2 >>> 24] << 24) | (SBOX1[(t1 >>> 16) & 0xff]) << 16 |
        (SBOX1[(t0 >>> 8) & 0xff]) << 8 | (SBOX1[t3 & 0xff]);

    s3 = (SBOX1[t3 >>> 24] << 24) | (SBOX1[(t2 >>> 16) & 0xff]) << 16 |
        (SBOX1[(t1 >>> 8) & 0xff]) << 8 | (SBOX1[t0 & 0xff]);

    s0 ^= xk[k + 0];
    s1 ^= xk[k + 1];
    s2 ^= xk[k + 2];
    s3 ^= xk[k + 3];

    writeUint32BE(s0, dst, 0);
    writeUint32BE(s1, dst, 4);
    writeUint32BE(s2, dst, 8);
    writeUint32BE(s3, dst, 12);
}
