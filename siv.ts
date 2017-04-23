// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { BlockCipher, BlockCipherContructor } from "@stablelib/blockcipher";
import { CMAC, dbl } from "@stablelib/cmac";
import { CTR } from "@stablelib/ctr";
import { wipe } from "@stablelib/wipe";
import { equal } from "@stablelib/constant-time";

/** Maximum number of associated data items */
export const MAX_ASSOCIATED_DATA = 126;

export class SIV {
    _mac: CMAC;
    _ctr: CTR | undefined;
    _macCipher: BlockCipher;
    _encCipher: BlockCipher;
    _tmp1: Uint8Array;
    _tmp2: Uint8Array;

    readonly tagLength: number;

    constructor(cipher: BlockCipherContructor, key: Uint8Array) {
        const macKey = key.subarray(0, key.length / 2 | 0);
        const encKey = key.subarray(key.length / 2 | 0);

        this._macCipher = new cipher(macKey);
        this._encCipher = new cipher(encKey);
        this._mac = new CMAC(this._macCipher);

        if (this._mac.digestLength !== this._mac.blockSize) {
            throw new Error("SIV: this implementation needs CMAC block size to equal tag length");
        }
        this.tagLength = this._mac.digestLength;

        this._tmp1 = new Uint8Array(this._mac.digestLength);
        this._tmp2 = new Uint8Array(this._mac.digestLength);
    }

    seal(associatedData: Uint8Array[], plaintext: Uint8Array, dst?: Uint8Array): Uint8Array {
        if (associatedData.length > MAX_ASSOCIATED_DATA) {
            throw new Error("SIV: too many associated data items");
        }

        // Allocate space for sealed ciphertext.
        const resultLength = this.tagLength + plaintext.length;
        let result;
        if (dst) {
            if (dst.length !== resultLength) {
                throw new Error("SIV: incorrect destination length");
            }
            result = dst;
        } else {
            result = new Uint8Array(resultLength);
        }

        // Authenticate.
        const iv = this._s2v(associatedData, plaintext);
        result.set(iv);

        // Encrypt.
        zeroIVBits(iv);
        this._streamXOR(iv, plaintext, result.subarray(iv.length));
        return result;
    }

    open(associatedData: Uint8Array[], sealed: Uint8Array, dst?: Uint8Array): Uint8Array | null {
        if (associatedData.length > MAX_ASSOCIATED_DATA) {
            throw new Error("SIV: too many associated data items");
        }
        if (sealed.length < this.tagLength) {
            return null;
        }

        // Allocate space for decrypted plaintext.
        const resultLength = sealed.length - this.tagLength;
        let result;
        if (dst) {
            if (dst.length !== resultLength) {
                throw new Error("SIV: incorrect destination length");
            }
            result = dst;
        } else {
            result = new Uint8Array(resultLength);
        }

        // Decrypt.
        const tag = sealed.subarray(0, this.tagLength);
        const iv = this._tmp1;
        iv.set(tag);
        zeroIVBits(iv);
        this._streamXOR(iv, sealed.subarray(this.tagLength), result);

        // Authenticate.
        const expectedTag = this._s2v(associatedData, result);
        if (!equal(expectedTag, tag)) {
            wipe(result);
            return null;
        }
        return result;
    }

    _streamXOR(iv: Uint8Array, src: Uint8Array, dst: Uint8Array) {
        if (!this._ctr) {
            this._ctr = new CTR(this._encCipher, iv);
        } else {
            this._ctr.setCipher(this._encCipher, iv);
        }
        this._ctr.streamXOR(src, dst);
        return dst;
    }

    _s2v(s: Uint8Array[], sn: Uint8Array): Uint8Array {
        if (!s) {
            s = [];
        }

        this._mac.reset();
        wipe(this._tmp1);

        // Note: the standalone S2V returns CMAC(1) if the number of passed
        // vectors is zero, however in SIV contruction this case is never
        // triggered, since we always pass plaintext as the last vector (even
        // if it's zero-length), so we omit this case.
        this._mac.update(this._tmp1);
        this._mac.finish(this._tmp2);
        this._mac.reset();

        for (let i = 0; i < s.length; i++) {
            this._mac.update(s[i]);
            this._mac.finish(this._tmp1);
            this._mac.reset();
            dbl(this._tmp2, this._tmp2);
            xor(this._tmp2, this._tmp1);
        }

        wipe(this._tmp1);

        if (sn.length >= this._mac.blockSize) {
            const n = sn.length - this._mac.blockSize;
            this._tmp1.set(sn.subarray(n));
            this._mac.update(sn.subarray(0, n));
        } else {
            this._tmp1.set(sn);
            this._tmp1[sn.length] = 0x80;
            dbl(this._tmp2, this._tmp2);
        }
        xor(this._tmp1, this._tmp2);
        this._mac.update(this._tmp1);
        this._mac.finish(this._tmp1);
        return this._tmp1;
    }

    clean() {
        wipe(this._tmp1);
        wipe(this._tmp2);
        if (this._ctr) {
            this._ctr.clean();
        }
        this._mac.clean();
        this._encCipher.clean();
        this._macCipher.clean();
        this.tagLength = 0;
    }
}

function xor(a: Uint8Array, b: Uint8Array) {
    for (let i = 0; i < b.length; i++) {
        a[i] ^= b[i];
    }
}

function zeroIVBits(iv: Uint8Array) {
    // "We zero-out the top bit in each of the last two 32-bit words
    // of the IV before assigning it to Ctr"
    //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
    iv[iv.length - 8] &= 0x7f;
    iv[iv.length - 4] &= 0x7f;
}
