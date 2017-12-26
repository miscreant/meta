import { ICTRLike } from "../../interfaces";

/**
 * AES-CTR using a WebCrypto (or similar) API
 */
export default class WebCryptoAesCtr implements ICTRLike {
  public static async importKey(crypto: Crypto, keyData: Uint8Array): Promise<WebCryptoAesCtr> {
    // Only AES-128 and AES-256 supported. AES-192 is not.
    if (keyData.length !== 16 && keyData.length !== 32) {
      throw new Error(`Miscreant: invalid key length: ${keyData.length} (expected 16 or 32 bytes)`);
    }

    const key = await crypto.subtle.importKey("raw", keyData, "AES-CTR", false, ["encrypt"]);
    return new WebCryptoAesCtr(key, crypto);
  }

  constructor(
    readonly key: CryptoKey,
    readonly crypto: Crypto,
  ) { }

  public async encryptCtr(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    const ciphertext = await this.crypto.subtle.encrypt(
      { name: "AES-CTR", counter: iv, length: 16 },
      this.key,
      plaintext,
    );

    return new Uint8Array(ciphertext);
  }

  public clear(): this {
    // TODO: actually clear something. Do we need to?
    return this;
  }
}
