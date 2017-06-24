import { ICtrLike } from "../interfaces";
import { defaultCryptoProvider } from "../util";

/** AES-CTR using a WebCrypto (or similar) API */
export default class WebCryptoAesCtr implements ICtrLike {
  public static async importKey(keyData: Uint8Array, crypto = defaultCryptoProvider()): Promise<WebCryptoAesCtr> {
    // Only AES-128 and AES-256 supported. AES-192 is not.
    if (keyData.length !== 16 && keyData.length !== 32) {
      throw new Error(`invalid key ${keyData.length} (expected 16 or 32 bytes)`);
    }

    const key = await crypto.subtle.importKey("raw", keyData, "AES-CTR", false, ["encrypt"]);
    return new WebCryptoAesCtr(key, crypto);
  }

  constructor(
    readonly key: CryptoKey,
    readonly crypto = defaultCryptoProvider(),
  ) { }

  public async encrypt(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    const ciphertext = await this.crypto.subtle.encrypt(
      { name: "AES-CTR", counter: iv, length: 16 },
      this.key,
      plaintext,
    );

    return new Uint8Array(ciphertext);
  }

  public async decrypt(iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
    // AES-CTR decryption is identical to encryption
    return this.encrypt(iv, ciphertext);
  }

  public clean(): this {
    // TODO: actually clean something. Do we need to?
    return this;
  }
}
