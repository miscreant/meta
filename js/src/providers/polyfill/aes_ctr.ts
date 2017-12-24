// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { ICTRLike } from "../../interfaces";
import Block from "../../internals/block";

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
export default class PolyfillAesCtr implements ICTRLike {
  private _counter: Block;
  private _buffer: Block;
  private _cipher: PolyfillAes;

  constructor(cipher: PolyfillAes) {
    // Set cipher.
    this._cipher = cipher;

    // Allocate space for counter.
    this._counter = new Block();

    // Allocate buffer for encrypted block.
    this._buffer = new Block();
  }

  public clear(): this {
    this._buffer.clear();
    this._counter.clear();
    this._cipher.clear();
    return this;
  }

  public async encryptCtr(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    if (iv.length !== Block.SIZE) {
      throw new Error("CTR: iv length must be equal to cipher block size");
    }

    // Copy IV to counter, overwriting it.
    this._counter.data.set(iv);

    // Set buffer position to length of buffer
    // so that the first cipher block is generated.
    let bufferPos = Block.SIZE;

    const result = new Uint8Array(plaintext.length);

    for (let i = 0; i < plaintext.length; i++) {
      if (bufferPos === Block.SIZE) {
        this._buffer.copy(this._counter);
        this._cipher.encryptBlock(this._buffer);
        bufferPos = 0;
        incrementCounter(this._counter);
      }
      result[i] = plaintext[i] ^ this._buffer.data[bufferPos++];
    }

    return result;
  }
}

// Increment an AES-CTR mode counter, intentionally wrapping/overflowing
function incrementCounter(counter: Block) {
  let carry = 1;

  for (let i = Block.SIZE - 1; i >= 0; i--) {
    carry += (counter.data[i] & 0xff) | 0;
    counter.data[i] = carry & 0xff;
    carry >>>= 8;
  }
}
