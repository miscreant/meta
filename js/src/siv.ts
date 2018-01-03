// Copyright (C) 2017-2018 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { equal } from "./internals/constant-time";
import { wipe } from "./internals/wipe";
import { xor } from "./internals/xor";

import { IntegrityError, NotImplementedError } from "./exceptions";
import { ICryptoProvider, ICTRLike, IMACLike, ISIVLike } from "./interfaces";
import Block from "./internals/block";

import { CMAC } from "./mac/cmac";
import { PMAC } from "./mac/pmac";

import { WebCryptoProvider } from "./providers/webcrypto";

/** Maximum number of associated data items */
export const MAX_ASSOCIATED_DATA = 126;

/** The AES-SIV mode of authenticated encryption */
export class SIV implements ISIVLike {
  /** Create a new AES-SIV instance with the given 32-byte or 64-byte key */
  public static async importKey(
    keyData: Uint8Array,
    alg: string,
    provider: ICryptoProvider = new WebCryptoProvider(),
  ): Promise<SIV> {
    // We only support AES-128 and AES-256. AES-SIV needs a key 2X as long the intended security level
    if (keyData.length !== 32 && keyData.length !== 64) {
      throw new Error(`AES-SIV: key must be 32 or 64-bytes (got ${keyData.length}`);
    }

    const macKey = keyData.subarray(0, keyData.length / 2 | 0);
    const encKey = keyData.subarray(keyData.length / 2 | 0);

    let mac: IMACLike;

    switch (alg) {
      case "AES-SIV":
        mac = await CMAC.importKey(provider, macKey);
        break;
      case "AES-CMAC-SIV":
        mac = await CMAC.importKey(provider, macKey);
        break;
      case "AES-PMAC-SIV":
        mac = await PMAC.importKey(provider, macKey);
        break;
      default:
        throw new NotImplementedError(`Miscreant: algorithm not supported: ${alg}`);
    }

    const ctr = await provider.importCTRKey(encKey);
    return new SIV(mac, ctr);
  }

  private _mac: IMACLike;
  private _ctr: ICTRLike;
  private _tmp1: Block;
  private _tmp2: Block;

  constructor(mac: IMACLike, ctr: ICTRLike) {
    this._mac = mac;
    this._ctr = ctr;
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
    result.set(await this._ctr.encryptCtr(iv, plaintext), iv.length);
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

    // NOTE: "encryptCtr" is intentional. CTR encryption/decryption are the same
    const result = await this._ctr.encryptCtr(iv, sealed.subarray(Block.SIZE));

    // Authenticate.
    const expectedTag = await this._s2v(associatedData, result);

    if (!equal(expectedTag, tag)) {
      wipe(result);
      throw new IntegrityError("AES-SIV: ciphertext verification failure!");
    }

    return result;
  }

  /** Make a best effort to wipe memory used by this instance */
  public clear(): this {
    this._tmp1.clear();
    this._tmp2.clear();
    this._ctr.clear();
    this._mac.clear();

    return this;
  }

  /**
   * The S2V operation consists of the doubling and XORing of the outputs
   * of the pseudo-random function CMAC (or PMAC in the case of AES-PMAC-SIV).
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
