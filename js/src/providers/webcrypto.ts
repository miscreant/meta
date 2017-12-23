import NotImplementedError from "../exceptions/not_implemented_error";
import { IBlockCipher, ICryptoProvider, ICTRLike } from "../internals/interfaces";
import WebCryptoAes from "./webcrypto/aes";
import WebCryptoAesCtr from "./webcrypto/aes_ctr";

/** Placeholder backend for using pure JavaScript crypto implementations */
export default class WebCryptoProvider implements ICryptoProvider {
  constructor(
    private crypto: Crypto = window.crypto,
  ) {
  }

  public async importAesKey(keyData: Uint8Array): Promise<IBlockCipher> {
    return WebCryptoAes.importKey(this.crypto, keyData);
  }

  public async importAesCtrKey(keyData: Uint8Array): Promise<ICTRLike> {
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
