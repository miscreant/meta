using System;
using System.Security.Cryptography;

namespace Miscreant
{
	/// <summary>
	/// AES-SIV authenticated encryption mode, defined in
	/// <see href="https://tools.ietf.org/html/rfc5297">RFC 5297</see>.
	/// </summary>
	public sealed class AesSiv : IDisposable
	{
		private const int BlockSize = Constants.BlockSize;
		private const int AesSiv256KeySize = 32;
		private const int AesSiv512KeySize = 64;
		private const int MaxAssociatedDataItems = 126;
		private const int MinimumRandomNonceSize = BlockSize;

		private static readonly byte[] Empty = new byte[0];
		private static readonly byte[] Zero = new byte[BlockSize];

		private readonly IMac mac;
		private readonly AesCtr ctr;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="AesSiv"/> class with the specified key.
		/// </summary>
		/// <param name="key">The secret key for <see cref="AesSiv"> encryption.</param>
		public AesSiv(byte[] key)
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}

			if (key.Length != AesSiv256KeySize && key.Length != AesSiv512KeySize)
			{
				throw new CryptographicException("Specified key is not a valid size for this algorithm.");
			}

			int halfKeySize = key.Length / 2;

			var K1 = new byte[halfKeySize];
			var K2 = new byte[halfKeySize];

			Array.Copy(key, 0, K1, 0, halfKeySize);
			Array.Copy(key, halfKeySize, K2, 0, halfKeySize);

			mac = new AesCmac(K1);
			ctr = new AesCtr(K2);
		}

		/// <summary>
		/// Generates a random nonce.
		/// </summary>
		/// <param name="size">Nonce size in bytes.</param>
		/// <returns>Generated nonce.</returns>
		public static byte[] GenerateNonce(int size)
		{
			if (size < MinimumRandomNonceSize)
			{
				throw new CryptographicException("Nonce size is too small.");
			}

			return Utils.GetRandomBytes(size);
		}

		/// <summary>
		/// Generates a random 32-byte encryption key.
		/// </summary>
		/// <returns>Generated key.</returns>
		public static byte[] GenerateKey256()
		{
			return Utils.GetRandomBytes(AesSiv256KeySize);
		}

		/// <summary>
		/// Generates a random 64-byte encryption key.
		/// </summary>
		/// <returns>Generated key.</returns>
		public byte[] GenerateKey512()
		{
			return Utils.GetRandomBytes(AesSiv512KeySize);
		}

		/// <summary>
		/// Seal encrypts and authenticates plaintext, authenticates the given
		/// associated data items, and returns the result. For nonce-based
		/// encryption, the nonce should be the last associated data item.
		/// </summary>
		/// <param name="plaintext">The plaintext to encrypt.</param>
		/// <param name="data">Associated data items to authenticate.</param>
		/// <returns>Concatenation of the authentication tag and the encrypted data.</returns>
		public byte[] Seal(byte[] plaintext, params byte[][] data)
		{
			if (data == null)
			{
				throw new ArgumentNullException(nameof(data));
			}

			if (data.Length > MaxAssociatedDataItems)
			{
				throw new CryptographicException($"Maximum number of associated data items is {MaxAssociatedDataItems}");
			}

			if (plaintext == null)
			{
				plaintext = Empty;
			}

			byte[] iv = S2V(data, plaintext);
			byte[] output = new byte[iv.Length + plaintext.Length];

			Array.Copy(iv, output, iv.Length);
			ZeroIvBits(iv);

			ctr.Reset(iv);
			ctr.Encrypt(plaintext, 0, plaintext.Length, output, iv.Length);

			return output;
		}

		/// <summary>
		/// Open decrypts ciphertext, authenticates the decrypted plaintext
		/// and the given associated data items and, if successful, returns
		/// the result. For nonce-based encryption, the nonce should be the
		/// last associated data item. In case of failed decryption, this
		/// method throws <see cref="CryptographicException">.
		/// </summary>
		/// <param name="ciphertext">The ciphertext to decrypt.</param>
		/// <param name="data">Associated data items to authenticate.</param>
		/// <returns>The decrypted plaintext.</returns>
		/// <exception cref="CryptographicException">Thrown when the ciphertext is invalid.</exception>
		public byte[] Open(byte[] ciphertext, params byte[][] data)
		{
			if (ciphertext == null)
			{
				throw new ArgumentNullException(nameof(ciphertext));
			}

			if (data == null)
			{
				throw new ArgumentNullException(nameof(data));
			}

			if (ciphertext.Length < BlockSize)
			{
				throw new CryptographicException("Malformed or corrupt ciphertext.");
			}

			if (data.Length > MaxAssociatedDataItems)
			{
				throw new CryptographicException($"Maximum number of associated data items is {MaxAssociatedDataItems}");
			}

			byte[] iv = new byte[BlockSize];
			byte[] output = new byte[ciphertext.Length - iv.Length];

			Array.Copy(ciphertext, 0, iv, 0, BlockSize);
			ZeroIvBits(iv);

			ctr.Reset(iv);
			ctr.Encrypt(ciphertext, BlockSize, output.Length, output, 0);

			byte[] v = S2V(data, output);

			if (!Utils.ConstantTimeEquals(ciphertext, v, BlockSize))
			{
				throw new CryptographicException("Malformed or corrupt ciphertext.");
			}

			return output;
		}

		/// <summary>
		/// S2V operation, defined in the section 2.4 of
		/// <see href="https://tools.ietf.org/html/rfc5297#section-2.4">RFC 5297</see>.
		/// </summary>
		private byte[] S2V(byte[][] headers, byte[] message)
		{
			if (headers == null)
			{
				throw new ArgumentNullException(nameof(headers));
			}

			if (message == null)
			{
				throw new ArgumentNullException(nameof(message));
			}

			// The standalone S2V returns CMAC(1) if the number of
			// passed vectors is zero, however in SIV contruction
			// this case is never triggered, since we always pass
			// plaintext as the last vector (even if it's zero-length),
			// so we omit this case.

			mac.HashCore(Zero, 0, BlockSize);
			byte[] v = mac.HashFinal();

			foreach (var header in headers)
			{
				if (header == null)
				{
					throw new ArgumentNullException(nameof(header));
				}

				mac.HashCore(header, 0, header.Length);
				Utils.Multiply(v);
				Utils.Xor(mac.HashFinal(), v, BlockSize);
			}

			if (message.Length > BlockSize)
			{
				int n = message.Length - BlockSize;

				mac.HashCore(message, 0, n);
				Utils.Xor(message, n, v, 0, BlockSize);
				mac.HashCore(v, 0, BlockSize);

				return mac.HashFinal();
			}

			byte[] padded = new byte[BlockSize];

			Array.Copy(message, padded, message.Length);
			Utils.Multiply(v);
			Utils.Pad(padded, message.Length);
			Utils.Xor(padded, v, BlockSize);
			mac.HashCore(v, 0, BlockSize);

			return mac.HashFinal();
		}

		private void ZeroIvBits(byte[] iv)
		{
			iv[iv.Length - 8] &= 0x7f;
			iv[iv.Length - 4] &= 0x7f;
		}

		public void Dispose()
		{
			if (!disposed)
			{
				mac.Dispose();
				ctr.Dispose();

				disposed = true;
			}
		}
	}
}
