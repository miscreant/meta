import NotImplementedError from "../../exceptions/not_implemented_error";
import { IBlockCipher, ICryptoProvider, ICtrLike } from "../interfaces";
import WebCryptoAes from "./aes";
import WebCryptoAesCtr from "./aes_ctr";

/** Placeholder backend for using pure JavaScript crypto implementations */
export default class WebCryptoProvider implements ICryptoProvider {
  constructor(
    private crypto: Crypto,
  ) {
    // This class doesn't do anything, it just signals that polyfill impls should be used
  }

  public async importAesKey(keyData: Uint8Array): Promise<IBlockCipher> {
    return WebCryptoAes.importKey(this.crypto, keyData);
  }

  public async importAesCtrKey(keyData: Uint8Array): Promise<ICtrLike> {
    try {
      return await WebCryptoAesCtr.importKey(this.crypto, keyData);
    } catch (e) {
      if (e.message.includes("unsupported")) {
        throw new NotImplementedError("WebCryptoProvider: AES-CTR unsupported. Use PolyfillCryptoProvider.");
      } else {
        throw e;
      }
    }
  }
}
