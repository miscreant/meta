/** Shared interfaces for cryptographic algorithms */

/** A cipher which provides a SIV-like interface and properties */
export interface ISivLike {
  seal(plaintext: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array>;
  open(sealed: Uint8Array, associatedData: Uint8Array[]): Promise<Uint8Array>;
  clear(): this;
}

/** A cipher which provides CTR (counter mode) encryption */
export interface ICtrLike {
  encrypt(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
  clear(): this;
}

/** An implementation of a message authentication code (MAC) */
export interface IMacLike {
  reset(): this;
  clear(): void;
  update(data: Uint8Array): Promise<this>;
  finish(): Promise<Uint8Array>;
}
