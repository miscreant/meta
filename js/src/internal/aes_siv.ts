// Copyright (C) 2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { equal } from "./constant-time";
import { dbl, defaultCryptoProvider, wipe, xor, zeroIVBits } from "./util";

import IntegrityError from "./exceptions/integrity_error";
import NotImplementedError from "./exceptions/not_implemented_error";
import { ICmacLike, ICtrLike, ISivLike } from "./interfaces";

import PolyfillAes from "./polyfill/aes";
import PolyfillAesCmac from "./polyfill/aes_cmac";
import PolyfillAesCtr from "./polyfill/aes_ctr";
import WebCryptoAesCmac from "./webcrypto/aes_cmac";
import WebCryptoAesCtr from "./webcrypto/aes_ctr";

/** Maximum number of associated data items */
const MAX_ASSOCIATED_DATA = 126;

/** The AES-SIV mode of authenticated encryption */
export default class AesSiv implements ISivLike {
  /** Create a new AesSiv instance with the given 32-byte or 64-byte key */
  public static async importKey(keyData: Uint8Array, crypto: Crypto | null = defaultCryptoProvider()): Promise<AesSiv> {
    // We only support AES-128 and AES-256. AES-SIV needs a key 2X as long the intended security level
    if (keyData.length !== 32 && keyData.length !== 64) {
      throw new Error(`AES-SIV: key must be 32 or 64-bits (got ${keyData.length}`);
    }

    const macKey = keyData.subarray(0, keyData.length / 2 | 0);
    const encKey = keyData.subarray(keyData.length / 2 | 0);

    if (crypto !== null) {
      try {
        const mac = await WebCryptoAesCmac.importKey(macKey, crypto);
        const ctr = await WebCryptoAesCtr.importKey(encKey, crypto);
        return new AesSiv(mac, ctr, crypto);
      } catch (e) {
        if (e.message.includes("unsupported")) {
          throw new NotImplementedError("AES-SIV: unsupported crypto backend (CTR missing). Use polyfill.");
        } else {
          throw e;
        }
      }
    } else {
      const mac = new PolyfillAesCmac(new PolyfillAes(macKey));
      const ctr = new PolyfillAesCtr(new PolyfillAes(encKey));
      return new AesSiv(mac, ctr, null);
    }
  }

  public tagLength: number;
  private _mac: ICmacLike;
  private _ctr: ICtrLike;
  private _tmp1: Uint8Array;
  private _tmp2: Uint8Array;
  private _crypto: Crypto | null;

  constructor(mac: ICmacLike, ctr: ICtrLike, crypto: Crypto | null = defaultCryptoProvider()) {
    this._mac = mac;
    this._ctr = ctr;
    this._crypto = crypto;
    this._tmp1 = new Uint8Array(this._mac.digestLength);
    this._tmp2 = new Uint8Array(this._mac.digestLength);

    this.tagLength = this._mac.digestLength;
  }

  /** Encrypt and authenticate data using AES-SIV */
  public async seal(plaintext: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array> {
    if (associatedData.length > MAX_ASSOCIATED_DATA) {
      throw new Error("AES-SIV: too many associated data items");
    }

    // Allocate space for sealed ciphertext.
    const resultLength = this.tagLength + plaintext.length;
    const result = new Uint8Array(resultLength);

    // Authenticate.
    const iv = await this._s2v(associatedData, plaintext);
    result.set(iv);

    // Encrypt.
    zeroIVBits(iv);
    result.set(await this._ctr.encrypt(iv, plaintext), iv.length);
    return result;
  }

  /** Decrypt and authenticate data using AES-SIV */
  public async open(sealed: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array> {
    if (associatedData.length > MAX_ASSOCIATED_DATA) {
      throw new Error("AES-SIV: too many associated data items");
    }

    if (sealed.length < this.tagLength) {
      throw new IntegrityError("AES-SIV: ciphertext is truncated");
    }

    // Decrypt.
    const tag = sealed.subarray(0, this.tagLength);
    const iv = this._tmp1;
    iv.set(tag);
    zeroIVBits(iv);

    const result = await this._ctr.decrypt(iv, sealed.subarray(this.tagLength));

    // Authenticate.
    const expectedTag = await this._s2v(associatedData, result);

    if (!equal(expectedTag, tag)) {
      wipe(result);
      throw new IntegrityError("AES-SIV: ciphertext verification failure!");
    }

    return result;
  }

  /** Make a best effort to wipe memory used by this AesSiv instance */
  public clean(): this {
    wipe(this._tmp1);
    wipe(this._tmp2);
    this._ctr.clean();
    this._mac.clean();
    this.tagLength = 0;

    return this;
  }

  private async _s2v(s: Uint8Array[], sn: Uint8Array): Promise<Uint8Array> {
    if (!s) {
      s = [];
    }

    this._mac.reset();
    wipe(this._tmp1);

    // Note: the standalone S2V returns CMAC(1) if the number of passed
    // vectors is zero, however in SIV construction this case is never
    // triggered, since we always pass plaintext as the last vector (even
    // if it's zero-length), so we omit this case.
    await this._mac.update(this._tmp1);
    wipe(this._tmp2);
    this._tmp2 = await this._mac.finish();
    this._mac.reset();

    for (const b of s) {
      await this._mac.update(b);
      wipe(this._tmp1);
      this._tmp1 = await this._mac.finish();
      this._mac.reset();
      dbl(this._tmp2, this._tmp2);
      xor(this._tmp2, this._tmp1);
    }

    wipe(this._tmp1);

    if (sn.length >= this._mac.blockSize) {
      const n = sn.length - this._mac.blockSize;
      this._tmp1.set(sn.subarray(n));
      await this._mac.update(sn.subarray(0, n));
    } else {
      this._tmp1.set(sn);
      this._tmp1[sn.length] = 0x80;
      dbl(this._tmp2, this._tmp2);
    }
    xor(this._tmp1, this._tmp2);
    await this._mac.update(this._tmp1);
    return this._mac.finish();
  }
}
