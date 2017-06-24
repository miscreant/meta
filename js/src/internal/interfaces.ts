/** Shared interfaces for cryptographic algorithms */

/** A cipher which provides a SIV-like interface and properties */
export interface ISivLike {
  seal(associatedData: Uint8Array[], plaintext: Uint8Array): Promise<Uint8Array>;
  open(associatedData: Uint8Array[], sealed: Uint8Array): Promise<Uint8Array>;
  clean(): this;
}

/** A cipher which provides CTR (counter mode) encryption */
export interface ICtrLike {
  encrypt(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array>;
  clean(): this;
}

/** An implementation of the CMAC message authentication code */
export interface ICmacLike {
  blockSize: number;
  digestLength: number;
  reset(): this;
  clean(): void;
  update(data: Uint8Array): Promise<this>;
  finish(): Promise<Uint8Array>;
}
