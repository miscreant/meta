/** miscreant.ts: Main entry point to the Miscreant library */

import NotImplementedError from "./exceptions/not_implemented_error";
import { ICryptoProvider, ISivLike } from "./internal/interfaces";

import AesSiv from "./internal/aes_siv";
import PolyfillCryptoProvider from "./internal/polyfill/provider";
import WebCryptoProvider from "./internal/webcrypto/provider";

/** Miscreant: A misuse-resistant symmetric encryption library */
export default class Miscreant {
  /** Import a key for the given algorithm. Valid algorithms: "AES-SIV" */
  public static async importKey(
    keyData: Uint8Array,
    alg: string,
    provider: ICryptoProvider = Miscreant.webCryptoProvider(),
  ): Promise<ISivLike> {
    if (alg === "AES-SIV") {
      return AesSiv.importKey(provider, keyData);
    } else {
      throw new Error(`unsupported algorithm: ${alg}`);
    }
  }

  /**
   * Autodetect and return the default WebCrypto provider for this environment.
   *
   * Cryptography providers returned by this function should implement
   * cryptography natively and not rely on JavaScript polyfills.
   */
  public static webCryptoProvider(crypto: Crypto = window.crypto): WebCryptoProvider {
    try {
      return new WebCryptoProvider(crypto);
    } catch (e) {
      // Handle the case where window is undefined because we're not in a browser
      if (e instanceof ReferenceError) {
        throw new NotImplementedError("Miscreant: window.crypto unavailable in this environment");
      } else {
        throw e;
      }
    }
  }

  /**
   * Obtain a polyfill cryptographic provider
   *
   * WARNING: The polyfill implementation is not constant-time and may have
   * potentially severe security issues, including leaking secret keys!
   *
   * Please use the Web Crypto provider if at all possible.
   */
  public static polyfillCryptoProvider(): PolyfillCryptoProvider {
    return new PolyfillCryptoProvider();
  }
}
