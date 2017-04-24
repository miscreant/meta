// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

/**
 * Block cipher.
 */
export interface BlockCipher {
  /**
   * Byte length of cipher block.
   */
  blockSize: number;

  /**
   * Sets a new key for cipher.
   */
  setKey(key: Uint8Array): this;

  /**
   * Encrypts one block of data in src and puts the result into dst.
   *
   * Src and dst may be equal, but otherwise must not overlap.
   */
  encryptBlock(src: Uint8Array, dst: Uint8Array): this;

  /**
   * Decrypts one block of data in src and puts the result into dst.
   *
   * Src and dst may be equal, but otherwise must not overlap.
   */
  decryptBlock(src: Uint8Array, dst: Uint8Array): this;

  /**
   * Wipes state from memory.
   */
  clean(): this;
}

export interface BlockCipherContructor {
  new (key: Uint8Array, noDecryption?: boolean): BlockCipher;
}
