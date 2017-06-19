// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { dbl, wipe } from "../util";

import AesPolyfill from "./aes";

/**
 * Polyfill for the AES-CMAC message authentication code
 *
 * Uses a non-constant-time (lookup table-based) AES polyfill.
 * See polyfill/aes.ts for more information on the security impact.
 */
export default class AesCmacPolyfill {
  public readonly blockSize = 16;
  public readonly digestLength = 16;

  private _subkey1: Uint8Array;
  private _subkey2: Uint8Array;

  private _state: Uint8Array;
  private _statePos = 0;

  private _finished = false;

  private _cipher: AesPolyfill;

  constructor(cipher: AesPolyfill) {
    this._cipher = cipher;

    // Allocate space.
    this._subkey1 = new Uint8Array(this.blockSize);
    this._subkey2 = new Uint8Array(this.blockSize);
    this._state = new Uint8Array(this.blockSize);

    // Generate subkeys.
    this._cipher.encryptBlock(this._subkey1, this._subkey1);
    dbl(this._subkey1, this._subkey1);
    dbl(this._subkey1, this._subkey2);
  }

  public reset(): this {
    wipe(this._state);
    this._statePos = 0;
    this._finished = false;
    return this;
  }

  public clean() {
    wipe(this._state);
    wipe(this._subkey1);
    wipe(this._subkey2);
    this._cipher.clean();
    this._statePos = 0;
  }

  public update(data: Uint8Array): this {
    const left = this.blockSize - this._statePos;
    let dataPos = 0;
    let dataLength = data.length;

    if (dataLength > left) {
      for (let i = 0; i < left; i++) {
        this._state[this._statePos + i] ^= data[i];
      }
      dataLength -= left;
      dataPos += left;
      this._cipher.encryptBlock(this._state, this._state);
      this._statePos = 0;
    }

    while (dataLength > this.blockSize) {
      for (let i = 0; i < this.blockSize; i++) {
        this._state[i] ^= data[dataPos + i];
      }
      dataLength -= this.blockSize;
      dataPos += this.blockSize;
      this._cipher.encryptBlock(this._state, this._state);
    }

    for (let i = 0; i < dataLength; i++) {
      this._state[this._statePos++] ^= data[dataPos + i];
    }
    return this;
  }

  public finish(out: Uint8Array): this {
    if (!this._finished) {
      // Select which subkey to use.
      const key = (this._statePos < this.digestLength) ? this._subkey2 : this._subkey1;

      // XOR in the subkey.
      for (let i = 0; i < this._state.length; i++) {
        this._state[i] ^= key[i];
      }

      // Pad if needed.
      if (this._statePos < this._state.length) {
        this._state[this._statePos] ^= 0x80;
      }

      // Encrypt state to get the final digest.
      this._cipher.encryptBlock(this._state, this._state);

      // Set finished flag.
      this._finished = true;
    }
    out.set(this._state);
    return this;
  }

  /**
   * Returns the final CMAC digest.
   */
  public digest(): Uint8Array {
    const out = new Uint8Array(this.digestLength);
    this.finish(out);
    return out;
  }

}
