// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { select } from "./constant-time";
import NotImplementedError from "./exceptions/not_implemented_error";

/** Perform the doubling operation described in the AES-SIV paper */
export function dbl(src: Uint8Array, dst: Uint8Array) {
  let carry = 0;
  for (let i = src.length - 1; i >= 0; i--) {
    const b = (src[i] >>> 7) & 0xff;
    dst[i] = (src[i] << 1) | carry;
    carry = b;
  }
  dst[dst.length - 1] ^= select(carry, 0x87, 0);
  carry = 0;
}

/**
 * Autodetect and return the default cryptography provider for this environment.
 *
 * Cryptography providers returned by this function should implement
 * cryptography natively and not rely on JavaScript polyfills.
 */
export function defaultCryptoProvider(): Crypto {
  try {
    return window.crypto;
  } catch (e) {
    // Handle the case where window is undefined because we're not in a browser
    if (e instanceof ReferenceError) {
      throw new NotImplementedError("AES-SIV: no default crypto provider for this environment. Use polyfill.");
    } else {
      throw e;
    }
  }
}

export type NumericArray = number[] | Uint8Array | Int8Array | Uint16Array
  | Int16Array | Uint32Array | Int32Array | Float32Array | Float64Array;

/**
 * Sets all values in the given array to zero and returns it.
 *
 * The fact that it sets bytes to zero can be relied on.
 *
 * There is no guarantee that this function makes data disappear from memory,
 * as runtime implementation can, for example, have copying garbage collector
 * that will make copies of sensitive data before we wipe it. Or that an
 * operating system will write our data to swap or sleep image. Another thing
 * is that an optimizing compiler can remove calls to this function or make it
 * no-op. There's nothing we can do with it, so we just do our best and hope
 * that everything will be okay and good will triumph over evil.
 */
export function wipe(array: NumericArray): NumericArray {
  // Right now it's similar to array.fill(0). If it turns
  // out that runtimes optimize this call away, maybe
  // we can try something else.
  for (let i = 0; i < array.length; i++) {
    array[i] = 0;
  }
  return array;
}

export function xor(a: Uint8Array, b: Uint8Array) {
  for (let i = 0; i < b.length; i++) {
    a[i] ^= b[i];
  }
}

export function zeroIVBits(iv: Uint8Array) {
  // "We zero-out the top bit in each of the last two 32-bit words
  // of the IV before assigning it to Ctr"
  //  — http://web.cs.ucdavis.edu/~rogaway/papers/siv.pdf
  iv[iv.length - 8] &= 0x7f;
  iv[iv.length - 4] &= 0x7f;
}
