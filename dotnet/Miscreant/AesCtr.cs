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
		private byte[] counter;
		private ArraySegment<byte> keyStream;
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

			var buffer = new byte[KeyStreamBufferSize];
			keyStream = new ArraySegment<byte>(buffer, 0, 0);
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="AesCtr"/> class with the
		/// specified key. For internal use only. The initialization vector will
		/// be set later by the <see cref="AesSiv"> object.
		/// </summary>
		/// <param name="key">The secret key for <see cref="AesCtr"> encryption.</param>
		internal AesCtr(byte[] key)
		{
			aes = Aes.Create();
			aes.Mode = CipherMode.ECB;

			encryptor = aes.CreateEncryptor(key, null);

			var buffer = new byte[KeyStreamBufferSize];
			keyStream = new ArraySegment<byte>(buffer, 0, 0);
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
				if (keyStream.Count == 0)
				{
					GenerateKeyStream(inputSeg.Count);
				}

				int count = Math.Min(inputSeg.Count, keyStream.Count);
				int keyStreamPosition = keyStream.Offset;
				int inputPosition = inputSeg.Offset;
				int outputPosition = outputSeg.Offset;

				for (int i = 0; i < count; ++i)
				{
					byte c = (byte)(keyStream.Array[keyStreamPosition + i] ^ input[inputPosition + i]);
					output[outputPosition + i] = c;
				}

				keyStream = keyStream.Slice(count);
				inputSeg = inputSeg.Slice(count);
				outputSeg = outputSeg.Slice(count);
			}
		}

		/// <summary>
		/// Reset the initialization vector. For internal use only. This
		/// method is needed in order to avoid creating heavyweight
		/// <see cref="AesCtr"> object every time we call
		/// <see cref="AesSiv.Seal"> or <see cref="AesSiv.Open"> methods.
		/// </summary>
		/// <param name="iv">The initialization vector for <see cref="AesCtr"> encryption.</param>
		internal void Reset(byte[] iv)
		{
			counter = iv;
			keyStream = new ArraySegment<byte>(keyStream.Array, 0, 0);
		}

		private void GenerateKeyStream(int inputCount)
		{
			int size = Math.Min(KeyStreamBufferSize, Utils.Ceil(inputCount, BlockSize) * BlockSize);
			byte[] array = keyStream.Array;

			for (int i = 0; i < size; i += BlockSize)
			{
				Array.Copy(counter, 0, array, i, BlockSize);
				IncrementCounter();
			}

			encryptor.TransformBlock(array, 0, size, array, 0);
			keyStream = new ArraySegment<byte>(array, 0, size);
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
				Array.Clear(keyStream.Array, 0, KeyStreamBufferSize);

				disposed = true;
			}
		}
	}
}
