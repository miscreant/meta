/** sivchain.ts: The AES-SIV encryption mode and CHAIN chaining mode */

import { ISivLike } from "./internal/interfaces";
import { defaultCryptoProvider } from "./internal/util";

import AesSiv from "./internal/aes_siv";

/** Common interface to AES-SIV algorithms */
export default class SIV {
  /** Import a key for the given algorithm. Valid algorithms: "AES-SIV" */
  public static async importKey(
    keyData: Uint8Array,
    alg: string,
    crypto: Crypto | null = defaultCryptoProvider(),
  ): Promise<ISivLike> {
    if (alg === "AES-SIV") {
      return AesSiv.importKey(keyData, crypto);
    } else {
      throw new Error(`unsupport algorithm: ${alg}`);
    }
  }
}
