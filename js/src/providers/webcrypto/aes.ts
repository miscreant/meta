// Copyright (C) 2017 Tony Arcieri
// MIT License. See LICENSE file for details.

import { IBlockCipher } from "../../interfaces";
import Block from "../../internals/block";

/**
 * WebCrypto-based implementation of the AES block cipher.
 *
 * This implementation (ab)uses AES-CBC mode to implement AES-ECB. This is
 * likely to be rather slow, as it requires an async call per block, and
 * discards half the buffer.
 *
 * In theory it should be constant time due to the use of WebCrypto (provided
 * the browser's implementation is constant time), but it could probably benefit
 * from some clever optimization work, or improvements to the WebCrypto API.
 *
 * Some WebCrypto implementations (e.g. node-webcrypto-ossl) support ECB mode
 * natively, so we could take advantage of that to potentially encrypt multiple
 * blocks in a single invocation.
 *
 * Key size: 16 or 32 bytes, block size: 16 bytes.
 */
export default class WebCryptoAes implements IBlockCipher {
  /**
   * Create a new WebCryptoAes instance
   *
   * @param {Crypto} crypto - the Web Cryptography provider
   * @param {Uint8Array} keyData - the AES secret key
   * @returns {Promise<WebCryptoAes}
   */
  public static async importKey(crypto: Crypto, keyData: Uint8Array): Promise<WebCryptoAes> {
    // Only AES-128 and AES-256 supported. AES-192 is not.
    if (keyData.length !== 16 && keyData.length !== 32) {
      throw new Error(`Miscreant: invalid key length: ${keyData.length} (expected 16 or 32 bytes)`);
    }

    const key = await crypto.subtle.importKey("raw", keyData, "AES-CBC", false, ["encrypt"]);
    return new WebCryptoAes(crypto, key);
  }

  // An initialization vector of all zeros, exposing the raw AES function
  private _iv = new Block();

  // A placeholder promise we always return to match the WebCrypto API
  private _emptyPromise: Promise<this>;

  constructor(
    private _crypto: Crypto,
    private _key: CryptoKey,
  ) {
    this._emptyPromise = Promise.resolve(this);
  }

  /**
   * Cleans expanded keys from memory, setting them to zeros.
   */
  public clear(): this {
    // TODO: perhaps we should clear something, but what, and how?
    return this;
  }

  /**
   * Encrypt a single AES block. While ordinarily this might let us see penguins, we're using it safely
   *
   * @param {Block} block - block to be encrypted in-place
   * @returns {Promise<this>}
   */
  public async encryptBlock(block: Block): Promise<this> {
    const params = { name: "AES-CBC", iv: this._iv.data };
    const ctBlock = await this._crypto.subtle.encrypt(params, this._key, block.data);

    // TODO: a more efficient way to do in-place encryption?
    block.data.set(new Uint8Array(ctBlock, 0, Block.SIZE));
    return this._emptyPromise;
  }
}
