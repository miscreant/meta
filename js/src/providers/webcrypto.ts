import { NotImplementedError } from "../exceptions";
import { IBlockCipher, ICryptoProvider, ICTRLike } from "../interfaces";
import WebCryptoAes from "./webcrypto/aes";
import WebCryptoAesCtr from "./webcrypto/aes_ctr";

/** Placeholder backend for using pure JavaScript crypto implementations */
export class WebCryptoProvider implements ICryptoProvider {
  constructor(
    private crypto: Crypto = window.crypto,
  ) {
  }

  public async importBlockCipherKey(keyData: Uint8Array): Promise<IBlockCipher> {
    return WebCryptoAes.importKey(this.crypto, keyData);
  }

  public async importCTRKey(keyData: Uint8Array): Promise<ICTRLike> {
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
