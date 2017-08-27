// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import Block from "../block";
import { IMacLike } from "../interfaces";
import { xor } from "../xor";
import PolyfillAes from "./aes";

/**
 * Polyfill for the AES-CMAC message authentication code
 *
 * Uses a non-constant-time (lookup table-based) AES polyfill.
 * See polyfill/aes.ts for more information on the security impact.
 */
export default class PolyfillAesCmac implements IMacLike {
  private _subkey1: Block;
  private _subkey2: Block;

  private _buffer: Block;
  private _bufferPos = 0;
  private _finished = false;

  private _cipher: PolyfillAes;

  constructor(cipher: PolyfillAes) {
    this._cipher = cipher;

    // Allocate space.
    this._subkey1 = new Block();
    this._subkey2 = new Block();
    this._buffer = new Block();

    // Generate subkeys.
    this._cipher.encryptBlock(this._subkey1);
    this._subkey1.dbl();
    this._subkey2.copy(this._subkey1);
    this._subkey2.dbl();
  }

  public reset(): this {
    this._buffer.clear();
    this._bufferPos = 0;
    this._finished = false;
    return this;
  }

  public clear() {
    this.reset();
    this._subkey1.clear();
    this._subkey2.clear();
    this._cipher.clear();
  }

  public async update(data: Uint8Array): Promise<this> {
    const left = Block.SIZE - this._bufferPos;
    let dataPos = 0;
    let dataLength = data.length;

    if (dataLength > left) {
      for (let i = 0; i < left; i++) {
        this._buffer.data[this._bufferPos + i] ^= data[i];
      }
      dataLength -= left;
      dataPos += left;
      this._cipher.encryptBlock(this._buffer);
      this._bufferPos = 0;
    }

    while (dataLength > Block.SIZE) {
      for (let i = 0; i < Block.SIZE; i++) {
        this._buffer.data[i] ^= data[dataPos + i];
      }
      dataLength -= Block.SIZE;
      dataPos += Block.SIZE;
      this._cipher.encryptBlock(this._buffer);
    }

    for (let i = 0; i < dataLength; i++) {
      this._buffer.data[this._bufferPos++] ^= data[dataPos + i];
    }

    return this;
  }

  public async finish(): Promise<Uint8Array> {
    if (!this._finished) {
      // Select which subkey to use.
      const subkey = (this._bufferPos < Block.SIZE) ? this._subkey2 : this._subkey1;

      // XOR in the subkey.
      xor(this._buffer.data, subkey.data);

      // Pad if needed.
      if (this._bufferPos < Block.SIZE) {
        this._buffer.data[this._bufferPos] ^= 0x80;
      }

      // Encrypt buffer to get the final digest.
      this._cipher.encryptBlock(this._buffer);

      // Set finished flag.
      this._finished = true;
    }

    const out = new Uint8Array(Block.SIZE);
    out.set(this._buffer.data);
    return out;
  }
}
