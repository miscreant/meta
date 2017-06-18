/** sivchain.ts: The AES-SIV encryption mode and CHAIN chaining mode */

import { AesSiv } from "./internal/aes_siv";
import { SivLike } from "./internal/interfaces";
import { defaultCryptoProvider } from "./internal/util";

/** Common interface to AES-SIV algorithms */
export class SIV {
  /** Import a key for the given algorithm. Valid algorithms: "AES-SIV" */
  static async importKey(
    keyData: Uint8Array,
    alg: string,
    crypto: Crypto | null = defaultCryptoProvider()
  ): Promise<SivLike> {
    if (alg === "AES-SIV") {
      return AesSiv.importKey(keyData, crypto);
    } else {
      throw new Error(`unsupport algorithm: ${alg}`);
    }
  }
}
