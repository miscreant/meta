/** Thrown when we attempt to use an unsupported crypto algorithm via WebCrypto */
export class NotImplementedError extends Error {
  constructor(m: string) {
    super(m);
    Object.setPrototypeOf(this, NotImplementedError.prototype);
  }
}
