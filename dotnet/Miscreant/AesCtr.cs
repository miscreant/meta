using System;
using System.Security.Cryptography;

namespace Miscreant
{
	/// <summary>
	/// Counter (CTR) mode, defined in NIST Special Publication
	/// <see href="https://csrc.nist.gov/publications/detail/sp/800-38a/final">SP 800-38A</see>.
	/// </summary>
	public sealed class AesCtr : IDisposable
	{
		private const int BlockSize = Constants.BlockSize;
		private const int KeyStreamBufferSize = 4096;

		private readonly Aes aes;
		private readonly ICryptoTransform encryptor;
		private readonly byte[] counter;
		private readonly byte[] keyStream;
		private int used;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="AesCtr"/> class with the specified key and initialization vector.
		/// </summary>
		/// <param name="key">The secret key for <see cref="AesCtr"> encryption.</param>
		/// <param name="iv">The initialization vector for <see cref="AesCtr"> encryption.</param>
		public AesCtr(byte[] key, byte[] iv)
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}

			if (iv == null)
			{
				throw new ArgumentNullException(nameof(iv));
			}

			if (iv.Length != BlockSize)
			{
				throw new CryptographicException("Specified initialization vector (IV) does not match the block size for this algorithm.");
			}

			aes = Aes.Create();
			aes.Mode = CipherMode.ECB;

			encryptor = aes.CreateEncryptor(key, null);
			counter = (byte[])iv.Clone();
			keyStream = new byte[KeyStreamBufferSize];

			GenerateKeyStream();
		}

		/// <summary>
		/// Encrypt/decrypt the input by xoring it with the CTR keystream.
		/// </summary>
		/// <param name="input">The input to encrypt.</param>
		/// <param name="inputOffset">The offset into the input byte array from which to begin using data.</param>
		/// <param name="inputCount">The number of bytes in the input byte array to use as data.</param>
		/// <param name="output">The output to which to write the encrypted data.</param>
		/// <param name="outputOffset">The offset into the output byte array from which to begin writing data.</param>
		public void Encrypt(byte[] input, int inputOffset, int inputCount, byte[] output, int outputOffset)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(AesCtr));
			}

			var inputSeg = new ArraySegment<byte>(input, inputOffset, inputCount);
			var outputSeg = new ArraySegment<byte>(output, outputOffset, inputCount);

			while (inputSeg.Count > 0)
			{
				if (used == KeyStreamBufferSize)
				{
					GenerateKeyStream();
				}

				int left = KeyStreamBufferSize - used;
				int count = Math.Min(inputSeg.Count, left);

				int inputPosition = inputSeg.Offset;
				int outputPosition = outputSeg.Offset;

				for (int i = 0; i < count; ++i)
				{
					byte c = (byte)(keyStream[used++] ^ input[inputPosition + i]);
					output[outputPosition + i] = c;
				}

				inputSeg = inputSeg.Slice(count);
				outputSeg = outputSeg.Slice(count);
			}
		}

		private void GenerateKeyStream()
		{
			for (int i = 0; i < KeyStreamBufferSize; i += BlockSize)
			{
				Array.Copy(counter, 0, keyStream, i, BlockSize);
				IncrementCounter();
			}

			encryptor.TransformBlock(keyStream, 0, KeyStreamBufferSize, keyStream, 0);
			used = 0;
		}

		private void IncrementCounter()
		{
			for (int i = BlockSize - 1; i >= 0; --i)
			{
				if (++counter[i] != 0)
				{
					break;
				}
			}
		}

		public void Dispose()
		{
			if (!disposed)
			{
				aes.Dispose();
				encryptor.Dispose();

				Array.Clear(counter, 0, BlockSize);
				Array.Clear(keyStream, 0, KeyStreamBufferSize);

				disposed = true;
			}
		}
	}
}
