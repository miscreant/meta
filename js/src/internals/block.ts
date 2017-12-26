/** Type which represents AES blocks */

import { select } from "./constant-time";
import { wipe } from "./wipe";

/** An AES block (128-bits) */
export default class Block {
  /** Size of a block as used by the AES cipher */
  public static readonly SIZE = 16;

  /** Minimal irreducible polynomial for a 128-bit block size */
  public static readonly R = 0x87;

  public data: Uint8Array;

  constructor() {
    this.data = new Uint8Array(Block.SIZE);
  }

  /**
   * Clear the given array by setting its values to zero.
   *
   * WARNING: The fact that it sets bytes to zero can be relied on.
   *
   * There is no guarantee that this function makes data disappear from memory,
   * as runtime implementation can, for example, have copying garbage collector
   * that will make copies of sensitive data before we wipe it. Or that an
   * operating system will write our data to swap or sleep image. Another thing
   * is that an optimizing compiler can remove calls to this function or make it
   * no-op. There's nothing we can do with it, so we just do our best and hope
   * that everything will be okay and good will triumph over evil.
   */
  public clear() {
    wipe(this.data);
  }

  /**
   * Make a copy of this block, returning a new block
   */
  public clone(): Block {
    const ret = new Block();
    ret.copy(this);
    return ret;
  }

  /** Copy the contents of another block into this one */
  public copy(other: Block) {
    this.data.set(other.data);
  }

  /**
   * Double a value over GF(2^128):
   *
   *     a<<1 if firstbit(a)=0
   *     (a<<1) ⊕ 0¹²⁰10000111 if firstbit(a)=1
   */
  public dbl() {
    let carry = 0;

    for (let i = Block.SIZE - 1; i >= 0; i--) {
      const b = (this.data[i] >>> 7) & 0xff;
      this.data[i] = (this.data[i] << 1) | carry;
      carry = b;
    }

    this.data[Block.SIZE - 1] ^= select(carry, Block.R, 0);
    carry = 0;
  }
}
