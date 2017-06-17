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
