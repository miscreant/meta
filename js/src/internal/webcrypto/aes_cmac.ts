// Copyright (C) 2016-2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import Block from "../block";
import { IMacLike } from "../interfaces";
import { xor } from "../xor";

/** WebCrypto-based implementation of the AES-CMAC message authentication code */
export default class WebCryptoAesCmac implements IMacLike {
  /** Create a new CMAC instance from the given key */
  public static async importKey(keyData: Uint8Array, crypto: Crypto): Promise<WebCryptoAesCmac> {
    // Only AES-128 and AES-256 supported. AES-192 is not.
    if (keyData.length !== 16 && keyData.length !== 32) {
      throw new Error(`invalid key ${keyData.length} (expected 16 or 32 bytes)`);
    }

    const key = await crypto.subtle.importKey("raw", keyData, "AES-CBC", false, ["encrypt"]);

    // Generate subkeys.
    const subkey1 = new Block();
    const subkey2 = new Block();

    await encryptBlock(crypto, key, subkey1);
    subkey1.dbl();

    subkey2.copy(subkey1);
    subkey2.dbl();

    return new WebCryptoAesCmac(key, subkey1, subkey2, crypto);
  }

  private _buffer: Block;
  private _bufferPos = 0;
  private _finished = false;

  constructor(
    private _key: CryptoKey,
    private _subkey1: Block,
    private _subkey2: Block,
    private _crypto: Crypto,
  ) {
    this._buffer = new Block();
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
      await encryptBlock(this._crypto, this._key, this._buffer);
      this._bufferPos = 0;
    }

    // TODO: use AES-CBC with a span of multiple blocks instead of encryptBlock
    // to encrypt many blocks in a single call to the WebCrypto API
    while (dataLength > Block.SIZE) {
      for (let i = 0; i < Block.SIZE; i++) {
        this._buffer.data[i] ^= data[dataPos + i];
      }
      dataLength -= Block.SIZE;
      dataPos += Block.SIZE;
      await encryptBlock(this._crypto, this._key, this._buffer);
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
      await encryptBlock(this._crypto, this._key, this._buffer);

      // Set finished flag.
      this._finished = true;
    }

    const out = new Uint8Array(Block.SIZE);
    out.set(this._buffer.data);
    return out;
  }
}

/** Encrypt a single AES block. While ordinarily this might let us see penguins, we're using it safely */
async function encryptBlock(crypto: Crypto, key: CryptoKey, block: Block): Promise<void> {
  const params = { name: "AES-CBC", iv: new Uint8Array(Block.SIZE) };
  const ctBuffer = await crypto.subtle.encrypt(params, key, block.data);

  // TODO: a more efficient way to do in-place encryption?
  block.data.set(new Uint8Array(ctBuffer, 0, Block.SIZE));
}
