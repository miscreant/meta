/**
 * The STREAM online authenticated encryption construction.
 * See <https://eprint.iacr.org/2015/189.pdf> for definition.
 */

// tslint:disable:max-classes-per-file

import { IAEADLike, ICryptoProvider } from "./interfaces";

import { AEAD } from "./aead";
import { WebCryptoProvider } from "./providers/webcrypto";

/** Size of a nonce required by STREAM in bytes */
export const NONCE_SIZE = 8;

/** Byte flag indicating this is the last block in the STREAM (otherwise 0) */
export const LAST_BLOCK_FLAG = 1;

/** Maximum value of the counter STREAM uses internally to identify messages */
export const COUNTER_MAX = 0xFFFFFFFF;

/**
 * A STREAM encryptor with a 32-bit counter, generalized for any AEAD algorithm
 *
 * This corresponds to the ℰ stream encryptor object as defined in the paper
 * Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
 */
export class StreamEncryptor {
  /** Create a new StreamEncryptor instance with the given key */
  public static async importKey(
    keyData: Uint8Array,
    nonce: Uint8Array,
    alg: string,
    provider: ICryptoProvider = new WebCryptoProvider(),
  ): Promise<StreamEncryptor> {
    return new StreamEncryptor(await AEAD.importKey(keyData, alg, provider), nonce);
  }

  private _aead: IAEADLike;
  private _nonce_encoder: NonceEncoder;

  constructor(aead: IAEADLike, nonce: Uint8Array) {
    this._aead = aead;
    this._nonce_encoder = new NonceEncoder(nonce);
  }

  /** Encrypt and authenticate data using the selected AEAD algorithm */
  public async seal(
    plaintext: Uint8Array,
    lastBlock: boolean = false,
    associatedData: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array> {
    return this._aead.seal(plaintext, this._nonce_encoder.next(lastBlock), associatedData);
  }

  /** Make a best effort to wipe memory used by this instance */
  public clear(): this {
    this._aead.clear();
    return this;
  }
}

/**
 * A STREAM decryptor with a 32-bit counter, generalized for any AEAD algorithm
 *
 * This corresponds to the 𝒟 stream decryptor object as defined in the paper
 * Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
 */
export class StreamDecryptor {
  /** Create a new StreamDecryptor instance with the given key */
  public static async importKey(
    keyData: Uint8Array,
    nonce: Uint8Array,
    alg: string,
    provider: ICryptoProvider = new WebCryptoProvider(),
  ): Promise<StreamDecryptor> {
    return new StreamDecryptor(await AEAD.importKey(keyData, alg, provider), nonce);
  }

  private _aead: IAEADLike;
  private _nonce_encoder: NonceEncoder;

  constructor(aead: IAEADLike, nonce: Uint8Array) {
    this._aead = aead;
    this._nonce_encoder = new NonceEncoder(nonce);
  }

  /** Decrypt and authenticate data using the selected AEAD algorithm */
  public async open(
    ciphertext: Uint8Array,
    lastBlock: boolean = false,
    associatedData: Uint8Array = new Uint8Array(0),
  ): Promise<Uint8Array> {
    return this._aead.open(ciphertext, this._nonce_encoder.next(lastBlock), associatedData);
  }

  /** Make a best effort to wipe memory used by this instance */
  public clear(): this {
    this._aead.clear();
    return this;
  }
}

/** Computes STREAM nonces based on the current position in the STREAM. */
class NonceEncoder {
  private buffer: ArrayBuffer;
  private view: DataView;
  private array: Uint8Array;
  private counter: number;
  private finished: boolean;

  constructor(noncePrefix: Uint8Array) {
    if (noncePrefix.length !== NONCE_SIZE) {
      throw new Error(`STREAM: nonce must be 8-bits (got ${noncePrefix.length}`);
    }

    this.buffer = new ArrayBuffer(NONCE_SIZE + 4 + 1);
    this.view = new DataView(this.buffer);
    this.array = new Uint8Array(this.buffer);
    this.array.set(noncePrefix);

    this.counter = 0;
    this.finished = false;
  }

  /** Compute the next nonce value, incrementing the internal counter */
  public next(lastBlock: boolean): Uint8Array {
    if (this.finished) {
      throw new Error("STREAM: already finished");
    }

    this.view.setInt32(8, this.counter, false);

    if (lastBlock) {
      this.view.setInt8(12, LAST_BLOCK_FLAG);
      this.finished = true;
    } else {
      this.counter += 1;
      if (this.counter > COUNTER_MAX) {
        throw new Error("STREAM counter overflowed");
      }
    }

    return this.array;
  }
}
