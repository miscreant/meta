import { IBlockCipher, ICryptoProvider, ICTRLike } from "../interfaces";
import PolyfillAes from "./polyfill/aes";
import PolyfillAesCtr from "./polyfill/aes_ctr";

/**
 * Pure JavaScript cryptography implementations
 *
 * WARNING: Not constant time! May leak keys or have other security issues.
 */
export class PolyfillCryptoProvider implements ICryptoProvider {
  constructor() {
    // This class doesn't do anything, it just signals that polyfill impls should be used
  }

  public async importBlockCipherKey(keyData: Uint8Array): Promise<IBlockCipher> {
    return new PolyfillAes(keyData);
  }

  public async importCTRKey(keyData: Uint8Array): Promise<ICTRLike> {
    return new PolyfillAesCtr(new PolyfillAes(keyData));
  }
}
