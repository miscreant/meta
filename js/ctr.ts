// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { BlockCipher } from "@stablelib/blockcipher";
import { wipe } from "@stablelib/wipe";

/**
 * CTR implements counter cipher mode.
 *
 * Note that CTR mode is malleable and generally should not be used without
 * authentication. Instead, use an authenticated encryption mode, such as GCM.
 */
export class CTR {
    private _counter: Uint8Array;
    private _buffer: Uint8Array;
    private _bufpos = 0;
    private _cipher: BlockCipher;

    constructor(cipher: BlockCipher, iv: Uint8Array) {
        // Allocate space for counter.
        this._counter = new Uint8Array(cipher.blockSize);

        // Allocate buffer for encrypted block.
        this._buffer = new Uint8Array(cipher.blockSize);

        // Set buffer position to length of buffer
        // so that the first cipher block is generated.
        this.setCipher(cipher, iv);
    }

    setCipher(cipher: BlockCipher, iv: Uint8Array): this {
        if (iv.length !== this._counter.length) {
            throw new Error("CTR: iv length must be equal to cipher block size");
        }

        // Set cipher.
        this._cipher = cipher;

        // Copy IV to counter, overwriting it.
        this._counter.set(iv);

        // Set buffer position to length of buffer
        // so that the first cipher block is generated.
        this._bufpos = this._buffer.length;
        return this;
    }

    clean(): this {
        wipe(this._buffer);
        wipe(this._counter);
        this._bufpos = this._buffer.length;
        // Cleaning cipher is caller's responsibility.
        return this;
    }

    private fillBuffer() {
        this._cipher.encryptBlock(this._counter, this._buffer);
        this._bufpos = 0;
        incrementCounter(this._counter);
    }

    streamXOR(src: Uint8Array, dst: Uint8Array): void {
        for (let i = 0; i < src.length; i++) {
            if (this._bufpos === this._buffer.length) {
                this.fillBuffer();
            }
            dst[i] = src[i] ^ this._buffer[this._bufpos++];
        }
    }

    stream(dst: Uint8Array): void {
        for (let i = 0; i < dst.length; i++) {
            if (this._bufpos === this._counter.length) {
                this.fillBuffer();
            }
            dst[i] = this._buffer[this._bufpos++];
        }
    }

}

function incrementCounter(counter: Uint8Array) {
    let carry = 1;
    for (let i = counter.length - 1; i >= 0; i--) {
        carry = carry + (counter[i] & 0xff) | 0;
        counter[i] = carry & 0xff;
        carry >>>= 8;
    }
    if (carry > 0) {
        throw new Error("CTR: counter overflow");
    }
}
