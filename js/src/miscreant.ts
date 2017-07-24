/** miscreant.ts: The AES-SIV encryption mode and CHAIN chaining mode */

import { ISivLike } from "./internal/interfaces";
import { defaultCryptoProvider } from "./internal/util";

import AesSiv from "./internal/aes_siv";
import PolyfillCrypto from "./internal/polyfill";

/** Common interface to AES-SIV algorithms */
export default class Miscreant {
  /** Import a key for the given algorithm. Valid algorithms: "AES-SIV" */
  public static async importKey(
    keyData: Uint8Array,
    alg: string,
    crypto: Crypto | PolyfillCrypto = defaultCryptoProvider(),
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
      return defaultCryptoProvider();
    } else if (providerName === "polyfill") {
      return new PolyfillCrypto();
    } else {
      throw new Error(`unsupported provider: ${providerName}`);
    }
  }
}
