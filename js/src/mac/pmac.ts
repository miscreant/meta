// Copyright (C) 2016-2017 Tony Arcieri, Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { IBlockCipher, ICryptoProvider, IMACLike } from "../interfaces";
import Block from "../internals/block";
import { select } from "../internals/constant-time";
import { ctz } from "../internals/ctz";
import { xor } from "../internals/xor";

// Number of L blocks to precompute (i.e. µ in the PMAC paper)
// TODO: dynamically compute these as needed
const PRECOMPUTED_BLOCKS: number = 31;

/**
 * Polyfill for the AES-PMAC message authentication code
 *
 * Uses a non-constant-time (lookup table-based) AES polyfill.
 * See polyfill/aes.ts for more information on the security impact.
 */
export class PMAC implements IMACLike {
  /** Create a new CMAC instance from the given key */
  public static async importKey(provider: ICryptoProvider, keyData: Uint8Array): Promise<PMAC> {
    const cipher = await provider.importBlockCipherKey(keyData);

    /**
     * L is defined as follows (quoted from the PMAC paper):
     *
     * Equation 1:
     *
     *     a · x =
     *         a<<1 if firstbit(a)=0
     *         (a<<1) ⊕ 0¹²⁰10000111 if firstbit(a)=1
     *
     * Equation 2:
     *
     *     a · x⁻¹ =
     *         a>>1 if lastbit(a)=0
     *         (a>>1) ⊕ 10¹²⁰1000011 if lastbit(a)=1
     *
     * Let L(0) ← L. For i ∈ [1..µ], compute L(i) ← L(i − 1) · x by
     * Equation (1) using a shift and a conditional xor.
     *
     * Compute L(−1) ← L · x⁻¹ by Equation (2), using a shift and a
     * conditional xor.
     *
     * Save the values L(−1), L(0), L(1), L(2), ..., L(µ) in a table.
     * (Alternatively, [ed: as we have done in this codebase] defer computing
     * some or  all of these L(i) values until the value is actually needed.)
     */
    const tmp = new Block();
    await cipher.encryptBlock(tmp);

    const l = new Array<Block>(PRECOMPUTED_BLOCKS);

    for (let i = 0; i < PRECOMPUTED_BLOCKS; i++) {
      l[i] = tmp.clone();
      tmp.dbl();
    }

    /**
     * Compute L(−1) ← L · x⁻¹:
     *
     *     a>>1 if lastbit(a)=0
     *     (a>>1) ⊕ 10¹²⁰1000011 if lastbit(a)=1
     */
    const lInv = l[0].clone();
    const lastBit = lInv.data[Block.SIZE - 1] & 0x01;

    for (let i = Block.SIZE - 1; i > 0; i--) {
      const carry = select(lInv.data[i - 1] & 1, 0x80, 0);
      lInv.data[i] = (lInv.data[i] >>> 1) | carry;
    }

    lInv.data[0] >>>= 1;
    lInv.data[0] ^= select(lastBit, 0x80, 0);
    lInv.data[Block.SIZE - 1] ^= select(lastBit, Block.R >>> 1, 0);

    return new PMAC(cipher, l, lInv);
  }

  /** The block cipher we're using (i.e. AES-128 or AES-256) */
  private _cipher: IBlockCipher;

  /** L is computed as described above, for up to PRECOMPUTED_BLOCKS */
  private _L: Block[];

  /**
   * L(-1) is computed as described above, and is XORed into the tag in the
   * event the message length is a multiple of the block size
   */
  private _LInv: Block;

  /** buffer is input plaintext, which we process a block-at-a-time */
  private _buffer: Block;

  /** bufferPos marks the end of plaintext in the buffer */
  private _bufferPos: number;

  /** counter is the number of blocks we have MAC'd so far */
  private _counter: number;

  /** offset is a block counter-specific tweak to the MAC value */
  private _offset: Block;

  /** tag is the PMAC tag-in-progress */
  private _tag: Block;

  /**
   * finished is set true when we are done processing a message, and forbids
   * any subsequent writes until we reset the internal state
   */
  private _finished: boolean = false;

  constructor(cipher: IBlockCipher, l: Block[], lInv: Block) {
    this._cipher = cipher;
    this._L = l;
    this._LInv = lInv;
    this._buffer = new Block();
    this._bufferPos = 0;
    this._counter = 0;
    this._offset = new Block();
    this._tag = new Block();
  }

  public reset(): this {
    this._buffer.clear();
    this._bufferPos = 0;
    this._counter = 0;
    this._offset.clear();
    this._tag.clear();
    this._finished = false;
    return this;
  }

  public clear() {
    this.reset();
    this._cipher.clear();
  }

  public async update(data: Uint8Array): Promise<this> {
    if (this._finished) {
      throw new Error("pmac: already finished");
    }

    const left = Block.SIZE - this._bufferPos;
    let dataPos = 0;
    let dataLength = data.length;

    // Finish filling the internal buf with the message
    if (dataLength > left) {
      this._buffer.data.set(data.slice(0, left), this._bufferPos);

      dataPos += left;
      dataLength -= left;

      await this._processBuffer();
    }

    // So long as we have more than a blocks worth of data, compute
    // whole-sized blocks at a time.
    while (dataLength > Block.SIZE) {
      this._buffer.data.set(data.slice(dataPos, dataPos + Block.SIZE));

      dataPos += Block.SIZE;
      dataLength -= Block.SIZE;

      await this._processBuffer();
    }

    if (dataLength > 0) {
      this._buffer.data.set(data.slice(dataPos, dataPos + dataLength), this._bufferPos);
      this._bufferPos += dataLength;
    }

    return this;
  }

  public async finish(): Promise<Uint8Array> {
    if (this._finished) {
      throw new Error("pmac: already finished");
    }

    if (this._bufferPos === Block.SIZE) {
      xor(this._tag.data, this._buffer.data);
      xor(this._tag.data, this._LInv.data);
    } else {
      xor(this._tag.data, this._buffer.data.slice(0, this._bufferPos));
      this._tag.data[this._bufferPos] ^= 0x80;
    }

    await this._cipher.encryptBlock(this._tag);
    this._finished = true;

    return this._tag.clone().data;
  }

  // Update the internal tag state based on the buffer contents
  private async _processBuffer() {
    xor(this._offset.data, this._L[ctz(this._counter + 1)].data);
    xor(this._buffer.data, this._offset.data);
    this._counter++;

    await this._cipher.encryptBlock(this._buffer);
    xor(this._tag.data, this._buffer.data);
    this._bufferPos = 0;
  }
}
