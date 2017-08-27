/** miscreant.ts: Main entry point to the Miscreant library */

import NotImplementedError from "./exceptions/not_implemented_error";
import { ISivLike } from "./internal/interfaces";

import AesSiv from "./internal/aes_siv";
import PolyfillCrypto from "./internal/polyfill";

/** Miscreant: A misuse-resistant symmetric encryption library */
export default class Miscreant {
  /** Import a key for the given algorithm. Valid algorithms: "AES-SIV" */
  public static async importKey(
    keyData: Uint8Array,
    alg: string,
    crypto: Crypto | PolyfillCrypto = Miscreant.defaultCryptoProvider(),
  ): Promise<ISivLike> {
    if (alg === "AES-SIV") {
      return AesSiv.importKey(keyData, crypto);
    } else {
      throw new Error(`unsupported algorithm: ${alg}`);
    }
  }

  /** Obtain a cryptographic provider */
  public static getCryptoProvider(providerName = "default"): Crypto | PolyfillCrypto {
    if (providerName === "default") {
      return Miscreant.defaultCryptoProvider();
    } else if (providerName === "polyfill") {
      return new PolyfillCrypto();
    } else {
      throw new Error(`unsupported provider: ${providerName}`);
    }
  }

  /**
   * Autodetect and return the default cryptography provider for this environment.
   *
   * Cryptography providers returned by this function should implement
   * cryptography natively and not rely on JavaScript polyfills.
   */
  public static defaultCryptoProvider(): Crypto {
    try {
      return window.crypto;
    } catch (e) {
      // Handle the case where window is undefined because we're not in a browser
      if (e instanceof ReferenceError) {
        throw new NotImplementedError("AES-SIV: no default crypto provider for this environment. Use polyfill.");
      } else {
        throw e;
      }
    }
  }
}
