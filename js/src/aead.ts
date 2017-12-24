import { IAEADLike, ICryptoProvider, ISIVLike } from "./interfaces";

import { WebCryptoProvider } from "./providers/webcrypto";
import { SIV } from "./siv";

/** AEAD interface provider for ISIVLike types */
export class AEAD implements IAEADLike {
  /** Create a new AEAD instance with the given key */
  public static async importKey(
    keyData: Uint8Array,
    alg: string,
    provider: ICryptoProvider = new WebCryptoProvider(),
  ): Promise<AEAD> {
    return new AEAD(await SIV.importKey(keyData, alg, provider));
  }

  private _siv: ISIVLike;

  constructor(siv: ISIVLike) {
    this._siv = siv;
  }

  /** Encrypt and authenticate data using AES-SIV */
  public async seal(
    plaintext: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array> {
    return this._siv.seal(plaintext, [associatedData, nonce]);
  }

  /** Decrypt and authenticate data using AES-SIV */
  public async open(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    associatedData: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array> {
    return this._siv.open(ciphertext, [associatedData, nonce]);
  }

  /** Make a best effort to wipe memory used by this instance */
  public clear(): this {
    this._siv.clear();
    return this;
  }
}
