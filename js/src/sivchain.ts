/** sivchain.ts: The AES-SIV encryption mode and CHAIN chaining mode */

import { AesSiv, SivLike } from "./internal/aes_siv";

/** Common interface to AES-SIV algorithms */
export class SIV {
  /** Import a key for the given algorithm. Valid algorithms: "AES-SIV" */
  static async importKey(keyData: Uint8Array, alg: string): Promise<SivLike> {
    if (alg == "AES-SIV") {
      return AesSiv.importKey(keyData);
    } else {
      throw new Error(`unsupport algorithm: ${alg}`);
    }
  }
}
