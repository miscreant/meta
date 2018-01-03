// tslint:disable:max-classes-per-file

/** Thrown when ciphertext fails to verify as authentic */
export class IntegrityError extends Error {
  constructor(m: string) {
    super(m);
    Object.setPrototypeOf(this, IntegrityError.prototype);
  }
}

/** Thrown when we attempt to use an unsupported crypto algorithm via WebCrypto */
export class NotImplementedError extends Error {
  constructor(m: string) {
    super(m);
    Object.setPrototypeOf(this, NotImplementedError.prototype);
  }
}
