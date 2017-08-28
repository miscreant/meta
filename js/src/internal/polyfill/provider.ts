import { IBlockCipher, ICryptoProvider, ICtrLike } from "../interfaces";
import PolyfillAes from "./aes";
import PolyfillAesCtr from "./aes_ctr";

/**
 * Pure JavaScript cryptography implementations
 *
 * WARNING: Not constant time! May leak keys or have other security issues.
 */
export default class PolyfillCryptoProvider implements ICryptoProvider {
  constructor() {
    // This class doesn't do anything, it just signals that polyfill impls should be used
  }

  public async importAesKey(keyData: Uint8Array): Promise<IBlockCipher> {
    return new PolyfillAes(keyData);
  }

  public async importAesCtrKey(keyData: Uint8Array): Promise<ICtrLike> {
    return new PolyfillAesCtr(new PolyfillAes(keyData));
  }
}
