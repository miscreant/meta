using System;
using System.Linq;
using System.Security.Cryptography;

namespace Miscreant
{
	/// <summary>
	/// CMAC message authentication code, defined in NIST Special Publication
	/// <see href="https://csrc.nist.gov/publications/detail/sp/800-38b/archive/2005-05-01">SP 800-38B</see>.
	/// </summary>
	public sealed class AesCmac : KeyedHashAlgorithm
	{
		private const int BlockSize = Constants.BlockSize;
		private const int BufferSize = 4096;
		private static readonly byte[] Zero = new byte[BlockSize];

		private Aes aes;
		private ICryptoTransform encryptor;
		private readonly byte[] buffer = new byte[BufferSize];
		private readonly byte[] K1 = new byte[BlockSize];
		private readonly byte[] K2 = new byte[BlockSize];
		private int position;

		/// <summary>
		/// Initializes a new instance of the <see cref="AesCmac"/> class with the specified key.
		/// </summary>
		/// <param name="key">The secret key for <see cref="AesCmac"> authentication.</param>
		public AesCmac(byte[] key)
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}

			KeyValue = (byte[])key.Clone();
			HashSizeValue = 8 * BlockSize;

			using (var aes = CreateAes(CipherMode.ECB))
			using (var encryptor = aes.CreateEncryptor(KeyValue, null))
			{
				encryptor.TransformBlock(Zero, 0, BlockSize, K1, 0);
				Utils.Multiply(K1);

				Array.Copy(K1, K2, BlockSize);
				Utils.Multiply(K2);
			}

			aes = CreateAes(CipherMode.CBC);
			encryptor = aes.CreateEncryptor(KeyValue, Zero);
		}

		public override byte[] Key
		{
			get => (byte[])KeyValue.Clone();
			set => throw new InvalidOperationException("AES-CMAC key cannot be modified.");
		}

		public override void Initialize()
		{
			aes.Dispose();
			encryptor.Dispose();

			aes = CreateAes(CipherMode.CBC);
			encryptor = aes.CreateEncryptor(KeyValue, Zero);

			Array.Clear(buffer, 0, BufferSize);
			position = 0;
		}

		protected override void HashCore(byte[] input, int index, int size)
		{
			var seg = new ArraySegment<byte>(input, index, size);
			var left = BlockSize - position;

			if (position > 0 && seg.Count > left)
			{
				Array.Copy(seg.Array, seg.Offset, buffer, position, left);
				encryptor.TransformBlock(buffer, 0, BlockSize, buffer, 0);
				seg = seg.Slice(left);
				position = 0;
			}

			while (seg.Count > BlockSize)
			{
				// Encrypting single block in .NET is extremely slow, so we want
				// to encrypt as much of the input as possible in a single call to
				// TransformBlock. TransformBlock expects valid output buffer, so
				// we pre-allocate 4KB buffer for this purpose.

				int count = Math.Min(BufferSize, (seg.Count - 1) / BlockSize * BlockSize);
				encryptor.TransformBlock(seg.Array, seg.Offset, count, buffer, 0);
				seg = seg.Slice(count);
			}

			if (seg.Count > 0)
			{
				Array.Copy(seg.Array, seg.Offset, buffer, position, seg.Count);
				position += seg.Count;
			}
		}

		protected override byte[] HashFinal()
		{
			if (position == BlockSize)
			{
				Utils.Xor(K1, buffer, BlockSize);
			}
			else
			{
				Utils.Pad(buffer, position);
				Utils.Xor(K2, buffer, BlockSize);
			}

			byte[] sum = new byte[BlockSize];
			encryptor.TransformBlock(buffer, 0, BlockSize, sum, 0);

			return sum;
		}

		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				aes.Dispose();
				encryptor.Dispose();

				Array.Clear(buffer, 0, BufferSize);
				Array.Clear(K1, 0, BlockSize);
				Array.Clear(K2, 0, BlockSize);
			}
		}

		private static Aes CreateAes(CipherMode mode)
		{
			var aes = Aes.Create();

			aes.Mode = mode;
			aes.Padding = PaddingMode.None;

			return aes;
		}
	}
}
