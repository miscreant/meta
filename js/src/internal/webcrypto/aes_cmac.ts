// Copyright (C) 2016 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { ICmacLike } from "../interfaces";
import { dbl, wipe } from "../util";
import { defaultCryptoProvider } from "../util";

/** Size of a block as used by the AES cipher */
const AES_BLOCK_SIZE = 16;

/** WebCrypto-based implementation of the AES-CMAC message authentication code */
export default class WebCryptoAesCmac implements ICmacLike {
  /** Create a new CMAC instance from the given key */
  public static async importKey(keyData: Uint8Array, crypto = defaultCryptoProvider()): Promise<WebCryptoAesCmac> {
    // Only AES-128 and AES-256 supported. AES-192 is not.
    if (keyData.length !== 16 && keyData.length !== 32) {
      throw new Error(`invalid key ${keyData.length} (expected 16 or 32 bytes)`);
    }

    const key = await crypto.subtle.importKey("raw", keyData, "AES-CBC", false, ["encrypt"]);

    // Generate subkeys.
    const zeroes = new Uint8Array(AES_BLOCK_SIZE);
    const subkey1 = await encryptBlock(crypto, key, zeroes);
    dbl(subkey1, subkey1);

    const subkey2 = new Uint8Array(AES_BLOCK_SIZE);
    dbl(subkey1, subkey2);

    return new WebCryptoAesCmac(key, subkey1, subkey2, crypto);
  }

  public readonly blockSize = AES_BLOCK_SIZE;
  public readonly digestLength = AES_BLOCK_SIZE;

  private _state: Uint8Array;
  private _statePos = 0;
  private _finished = false;

  constructor(
    private _key: CryptoKey,
    private _subkey1: Uint8Array,
    private _subkey2: Uint8Array,
    private _crypto = defaultCryptoProvider(),
  ) {
    this._state = new Uint8Array(AES_BLOCK_SIZE);
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
    this._statePos = 0;
  }

  public async update(data: Uint8Array): Promise<this> {
    const left = AES_BLOCK_SIZE - this._statePos;
    let dataPos = 0;
    let dataLength = data.length;

    if (dataLength > left) {
      for (let i = 0; i < left; i++) {
        this._state[this._statePos + i] ^= data[i];
      }
      dataLength -= left;
      dataPos += left;
      this._state = await encryptBlock(this._crypto, this._key, this._state);
      this._statePos = 0;
    }

    // TODO: use AES-CBC with a span of multiple blocks instead of encryptBlock
    // to encrypt many blocks in a single call to the WebCrypto API
    while (dataLength > AES_BLOCK_SIZE) {
      for (let i = 0; i < AES_BLOCK_SIZE; i++) {
        this._state[i] ^= data[dataPos + i];
      }
      dataLength -= AES_BLOCK_SIZE;
      dataPos += AES_BLOCK_SIZE;
      this._state = await encryptBlock(this._crypto, this._key, this._state);
    }

    for (let i = 0; i < dataLength; i++) {
      this._state[this._statePos++] ^= data[dataPos + i];
    }

    return this;
  }

  public async finish(): Promise<Uint8Array> {
    if (!this._finished) {
      // Select which subkey to use.
      const key = (this._statePos < AES_BLOCK_SIZE) ? this._subkey2 : this._subkey1;

      // XOR in the subkey.
      for (let i = 0; i < this._state.length; i++) {
        this._state[i] ^= key[i];
      }

      // Pad if needed.
      if (this._statePos < this._state.length) {
        this._state[this._statePos] ^= 0x80;
      }

      // Encrypt state to get the final digest.
      this._state = await encryptBlock(this._crypto, this._key, this._state);

      // Set finished flag.
      this._finished = true;
    }

    const out = new Uint8Array(AES_BLOCK_SIZE);
    out.set(this._state);
    return out;
  }
}

/** Encrypt a single AES block. While ordinarily this might let us see penguins, we're using it safely */
async function encryptBlock(crypto: Crypto, key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const params = { name: "AES-CBC", iv: new Uint8Array(AES_BLOCK_SIZE) };
  const buffer = await crypto.subtle.encrypt(params, key, plaintext);
  return new Uint8Array(buffer, 0, AES_BLOCK_SIZE);
}
