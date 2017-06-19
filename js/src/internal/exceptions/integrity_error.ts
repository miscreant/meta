/** Thrown when ciphertext fails to verify as authentic */
export default class IntegrityError extends Error {
  constructor(m: string) {
    super(m);
    Object.setPrototypeOf(this, IntegrityError.prototype);
  }
}
