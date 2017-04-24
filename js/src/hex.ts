// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

//        0123456789  ABCDEF  | abcdef
// Index:    0 - 9    10-15   | 10-15
// ASCII:   48 - 57   65-70   | 97-102

function encodeNibble(b: number): string {
  // b >= 0
  let result = b + 48;
  // b > 9
  result += ((9 - b) >>> 8) & (-48 + 65 - 10);

  return String.fromCharCode(result);
}

function encodeNibbleLower(b: number): string {
  // b >= 0
  let result = b + 48;
  // b > 9
  result += ((9 - b) >>> 8) & (-48 + 97 - 10);

  return String.fromCharCode(result);
}

// Invalid character used in decoding to indicate
// that the character to decode is out of range of
// hex alphabet and cannot be decoded.
const INVALID_HEX_NIBBLE = 256;

function decodeNibble(c: number): number {
  let result = INVALID_HEX_NIBBLE;

  // 0-9: c > 47 and c < 58
  result += (((47 - c) & (c - 58)) >> 8) & (-INVALID_HEX_NIBBLE + c - 48);
  // A-F: c > 64 and c < 71
  result += (((64 - c) & (c - 71)) >> 8) & (-INVALID_HEX_NIBBLE + c - 65 + 10);
  // a-f: c > 96 and c < 103
  result += (((96 - c) & (c - 103)) >> 8) & (-INVALID_HEX_NIBBLE + c - 97 + 10);

  return result;
}

/**
 * Returns string with hex-encoded data.
 */
export function encode(data: Uint8Array, lowerCase = false): string {
  const enc = lowerCase ? encodeNibbleLower : encodeNibble;
  let s = "";
  for (let i = 0; i < data.length; i++) {
    s += enc(data[i] >>> 4);
    s += enc(data[i] & 0x0f);
  }
  return s;
}

/**
 * Returns Uint8Array with data decoded from hex string.
 *
 * Throws error if hex string length is not divisible by 2 or has non-hex
 * characters.
 */
export function decode(hex: string): Uint8Array {
  if (hex.length === 0) {
    return new Uint8Array(0);
  }
  if (hex.length % 2 !== 0) {
    throw new Error("hex: input string must be divisible by two");
  }
  const result = new Uint8Array(hex.length / 2);
  let haveBad = 0;
  for (let i = 0; i < hex.length; i += 2) {
    let v0 = decodeNibble(hex.charCodeAt(i));
    let v1 = decodeNibble(hex.charCodeAt(i + 1));

    result[i / 2] = v0 << 4 | v1;

    haveBad |= v0 & INVALID_HEX_NIBBLE;
    haveBad |= v1 & INVALID_HEX_NIBBLE;
  }
  if (haveBad !== 0) {
    throw new Error("hex: incorrect characters for decoding");
  }
  return result;
}
