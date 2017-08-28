// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/** Perform an in-place bitwise XOR operation on two bytestrings */
export function xor(a: Uint8Array, b: Uint8Array) {
  for (let i = 0; i < b.length; i++) {
    a[i] ^= b[i];
  }
}
