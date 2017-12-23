/** Shared interfaces for cryptographic algorithms */

import Block from "./internals/block";

/**
 * A block cipher (with 128-bit blocks, i.e. AES)
 *
 * WARNING: This interface should not be used directly!
 * It should only be used to implement a cipher mode.
 * This library uses it to implement AES-SIV.
 */
export interface IBlockCipher {
  /** Zero out internal state (which may contain secrets */
  clear(): this;

  /** Encrypt 16-byte block in-place, replacing its contents with ciphertext. */
  encryptBlock(block: Block): Promise<this>;
}

/**
 * A backend which provides an implementation of cryptographic primitives
 */
export interface ICryptoProvider {
  importBlockCipherKey(keyData: Uint8Array): Promise<IBlockCipher>;
  importCTRKey(keyData: Uint8Array): Promise<ICTRLike>;
}

/**
 * A cipher which provides CTR (counter mode) encryption
 */
export interface ICTRLike {
  encryptCtr(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  clear(): this;
}

/**
 * An implementation of a message authentication code (MAC)
 */
export interface IMACLike {
  reset(): this;
  clear(): void;
  update(data: Uint8Array): Promise<this>;
  finish(): Promise<Uint8Array>;
}

/**
 * A cipher which provides a SIV-like interface and properties
 */
export interface ISIVLike {
  seal(plaintext: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array>;
  open(ciphertext: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array>;
  clear(): this;
}

/**
 * A cipher which provides an Authenticated Encryption with Associated Data (AEAD) interface
 */
export interface IAEADLike {
  seal(plaintext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>;
  open(ciphertext: Uint8Array, nonce: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>;
  clear(): this;
}
