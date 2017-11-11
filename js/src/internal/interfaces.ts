/** Shared interfaces for cryptographic algorithms */

import Block from "./block";

/**
 * A block cipher (with 128-bit blocks, i.e. AES)
 *
 *
 * WARNING: This interface should not be used directly!
 * That is why it is hiding under internal.
 *
 * It should only be used to implement a cipher mode.
 * This library uses it to implement AES-SIV.
 */
export interface IBlockCipher {
  clear(): this;

  /** Encrypt 16-byte block in-place, replacing its contents with ciphertext. */
  encryptBlock(block: Block): Promise<this>;
}

/**
 * A backend which provides an implementation of cryptographic primitives
 */
export interface ICryptoProvider {
  importAesKey(keyData: Uint8Array): Promise<IBlockCipher>;
  importAesCtrKey(keyData: Uint8Array): Promise<ICtrLike>;
}

/**
 * A cipher which provides CTR (counter mode) encryption
 */
export interface ICtrLike {
  encryptCtr(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  clear(): this;
}

/**
 * An implementation of a message authentication code (MAC)
 */
export interface IMacLike {
  reset(): this;
  clear(): void;
  update(data: Uint8Array): Promise<this>;
  finish(): Promise<Uint8Array>;
}

/**
 * A cipher which provides a SIV-like interface and properties
 */
export interface ISivLike {
  seal(
    plaintext: Uint8Array,
    associatedData: Uint8Array[]
  ): Promise<Uint8Array>;
  open(sealed: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array>;
  clear(): this;
}
