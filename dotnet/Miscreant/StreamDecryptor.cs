using System;
using System.Security.Cryptography;

namespace Miscreant
{
	/// <summary>
	/// STREAM online authenticated encryption, defined in the paper
	/// <see href="https://eprint.iacr.org/2015/189.pdf">
	/// Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance
	/// </see>.
	/// </summary>
	public sealed class StreamDecryptor : IDisposable
	{
		private readonly AesSiv siv;
		private readonly NonceEncoder nonce;
		private bool finished;
		private bool disposed;

		private StreamDecryptor(AesSiv siv, byte[] nonce)
		{
			this.siv = siv;
			this.nonce = new NonceEncoder(nonce);
		}

		/// <summary>
		/// Initializes a new instance of the STREAM decryptor using the AES-CMAC-SIV algorithm.
		/// </summary>
		/// <param name="key">The secret key for decryption.</param>
		/// <param name="nonce">The nonce for decryption.</param>
		/// <returns>A STREAM decryptor instance.</returns>
		public static StreamDecryptor CreateAesCmacSivDecryptor(byte[] key, byte[] nonce)
		{
			var siv = AesSiv.CreateAesCmacSiv(key);
			return new StreamDecryptor(siv, nonce);
		}

		/// <summary>
		/// Initializes a new instance of the STREAM decryptor using the AES-PMAC-SIV algorithm.
		/// </summary>
		/// <param name="key">The secret key for decryption.</param>
		/// <param name="nonce">The nonce for decryption.</param>
		/// <returns>A STREAM decryptor instance.</returns>
		public static StreamDecryptor CreateAesPmacSivDecryptor(byte[] key, byte[] nonce)
		{
			var siv = AesSiv.CreateAesPmacSiv(key);
			return new StreamDecryptor(siv, nonce);
		}

		/// <summary>
		/// Open decrypts the next ciphertext in the STREAM, authenticates the
		/// decrypted plaintext and the associated data and, if successful, returns
		/// the result. In case of failed decryption, this method throws
		/// <see cref="CryptographicException">.
		/// </summary>
		/// <param name="ciphertext">The ciphertext to decrypt.</param>
		/// <param name="data">Associated data items to authenticate.</param>
		/// <param name="last">True if this is the last block in the STREAM.</param>
		/// <returns>The decrypted plaintext.</returns>
		/// <exception cref="CryptographicException">Thrown when the ciphertext is invalid.</exception>
		public byte[] Open(byte[] ciphertext, byte[] data = null, bool last = false)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(StreamEncryptor));
			}

			if (finished)
			{
				throw new CryptographicException("STREAM is already finished.");
			}

			finished = last;

			return siv.Open(ciphertext, data, nonce.Next(last));
		}

		public void Dispose()
		{
			if (!disposed)
			{
				siv.Dispose();
				disposed = true;
			}
		}
	}
}
