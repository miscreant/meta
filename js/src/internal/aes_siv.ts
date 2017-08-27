// Copyright (C) 2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { equal } from "./constant-time";
import { wipe } from "./wipe";
import { xor } from "./xor";

import IntegrityError from "../exceptions/integrity_error";
import NotImplementedError from "../exceptions/not_implemented_error";
import Block from "./block";
import { ICtrLike, IMacLike, ISivLike } from "./interfaces";

import PolyfillCrypto from "./polyfill";
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
  public static async importKey(
    keyData: Uint8Array,
    crypto: Crypto | PolyfillCrypto,
  ): Promise<AesSiv> {
    // We only support AES-128 and AES-256. AES-SIV needs a key 2X as long the intended security level
    if (keyData.length !== 32 && keyData.length !== 64) {
      throw new Error(`AES-SIV: key must be 32 or 64-bits (got ${keyData.length}`);
    }

    const macKey = keyData.subarray(0, keyData.length / 2 | 0);
    const encKey = keyData.subarray(keyData.length / 2 | 0);

    if (crypto instanceof PolyfillCrypto) {
      const mac = new PolyfillAesCmac(new PolyfillAes(macKey));
      const ctr = new PolyfillAesCtr(new PolyfillAes(encKey));
      return new AesSiv(mac, ctr, null);
    } else {
      const mac = await WebCryptoAesCmac.importKey(macKey, crypto);

      try {
        const ctr = await WebCryptoAesCtr.importKey(encKey, crypto);
        return new AesSiv(mac, ctr, crypto);
      } catch (e) {
        if (e.message.includes("unsupported")) {
          throw new NotImplementedError("AES-SIV: unsupported crypto backend (CTR missing). Use PolyfillCrypto.");
        } else {
          throw e;
        }
      }
    }
  }

  private _mac: IMacLike;
  private _ctr: ICtrLike;
  private _tmp1: Block;
  private _tmp2: Block;
  private _crypto: Crypto | null;

  constructor(mac: IMacLike, ctr: ICtrLike, crypto: Crypto | null) {
    this._mac = mac;
    this._ctr = ctr;
    this._crypto = crypto;
    this._tmp1 = new Block();
    this._tmp2 = new Block();
  }

  /** Encrypt and authenticate data using AES-SIV */
  public async seal(plaintext: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array> {
    if (associatedData.length > MAX_ASSOCIATED_DATA) {
      throw new Error("AES-SIV: too many associated data items");
    }

    // Allocate space for sealed ciphertext.
    const resultLength = Block.SIZE + plaintext.length;
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

    if (sealed.length < Block.SIZE) {
      throw new IntegrityError("AES-SIV: ciphertext is truncated");
    }

    // Decrypt.
    const tag = sealed.subarray(0, Block.SIZE);
    const iv = this._tmp1.data;
    iv.set(tag);
    zeroIVBits(iv);

    const result = await this._ctr.decrypt(iv, sealed.subarray(Block.SIZE));

    // Authenticate.
    const expectedTag = await this._s2v(associatedData, result);

    if (!equal(expectedTag, tag)) {
      wipe(result);
      throw new IntegrityError("AES-SIV: ciphertext verification failure!");
    }

    return result;
  }

  /** Make a best effort to wipe memory used by this AesSiv instance */
  public clear(): this {
    this._tmp1.clear();
    this._tmp2.clear();
    this._ctr.clear();
    this._mac.clear();

    return this;
  }

  /**
   * The S2V operation consists of the doubling and XORing of the outputs
   * of the pseudo-random function CMAC.
   *
   * See Section 2.4 of RFC 5297 for more information
   */
  private async _s2v(associated_data: Uint8Array[], plaintext: Uint8Array): Promise<Uint8Array> {
    this._mac.reset();
    this._tmp1.clear();

    // Note: the standalone S2V returns CMAC(1) if the number of passed
    // vectors is zero, however in SIV construction this case is never
    // triggered, since we always pass plaintext as the last vector (even
    // if it's zero-length), so we omit this case.
    await this._mac.update(this._tmp1.data);
    this._tmp2.clear();
    this._tmp2.data.set(await this._mac.finish());
    this._mac.reset();

    for (const ad of associated_data) {
      await this._mac.update(ad);
      this._tmp1.clear();
      this._tmp1.data.set(await this._mac.finish());
      this._mac.reset();
      this._tmp2.dbl();
      xor(this._tmp2.data, this._tmp1.data);
    }

    this._tmp1.clear();

    if (plaintext.length >= Block.SIZE) {
      const n = plaintext.length - Block.SIZE;
      this._tmp1.data.set(plaintext.subarray(n));
      await this._mac.update(plaintext.subarray(0, n));
    } else {
      this._tmp1.data.set(plaintext);
      this._tmp1.data[plaintext.length] = 0x80;
      this._tmp2.dbl();
    }
    xor(this._tmp1.data, this._tmp2.data);
    await this._mac.update(this._tmp1.data);
    return this._mac.finish();
  }
}

/** Zero out the top bits in the last 32-bit words of the IV */
function zeroIVBits(iv: Uint8Array) {
  // "We zero-out the top bit in each of the last two 32-bit words
  // of the IV before assigning it to Ctr"
  //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
  iv[iv.length - 8] &= 0x7f;
  iv[iv.length - 4] &= 0x7f;
}
