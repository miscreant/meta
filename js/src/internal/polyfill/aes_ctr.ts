// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { ICtrLike } from "../interfaces";
import { wipe } from "../util";

import PolyfillAes from "./aes";

/**
 * Polyfill for the AES-CTR (counter) mode of operation.
 *
 * Uses a non-constant-time (lookup table-based) AES polyfill.
 * See polyfill/aes.ts for more information on the security impact.
 *
 * Note that CTR mode is malleable and generally should not be used without
 * authentication. Instead, use an authenticated encryption mode, like AES-SIV!
 */
export default class PolyfillAesCtr implements ICtrLike {
  private _counter: Uint8Array;
  private _buffer: Uint8Array;
  private _cipher: PolyfillAes;

  constructor(cipher: PolyfillAes) {
    // Set cipher.
    this._cipher = cipher;

    // Allocate space for counter.
    this._counter = new Uint8Array(cipher.blockSize);

    // Allocate buffer for encrypted block.
    this._buffer = new Uint8Array(cipher.blockSize);
  }

  public async encrypt(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    if (iv.length !== this._counter.length) {
      throw new Error("CTR: iv length must be equal to cipher block size");
    }

    // Copy IV to counter, overwriting it.
    this._counter.set(iv);

    // Set buffer position to length of buffer
    // so that the first cipher block is generated.
    let bufpos = this._buffer.length;

    const result = new Uint8Array(plaintext.length);

    for (let i = 0; i < plaintext.length; i++) {
      if (bufpos === this._buffer.length) {
        this._cipher.encryptBlock(this._counter, this._buffer);
        bufpos = 0;
        incrementCounter(this._counter);
      }
      result[i] = plaintext[i] ^ this._buffer[bufpos++];
    }

    return result;
  }

  public async decrypt(iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
    // AES-CTR decryption is identical to encryption
    return this.encrypt(iv, ciphertext);
  }

  public clean(): this {
    wipe(this._buffer);
    wipe(this._counter);
    this._cipher.clean();
    return this;
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
