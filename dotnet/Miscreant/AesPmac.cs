using System;
using System.Linq;
using System.Security.Cryptography;

namespace Miscreant
{
	/// <summary>
	/// PMAC message authentication code, defined in the paper
	/// <see href="http://web.cs.ucdavis.edu/~rogaway/ocb/pmac.pdf">
	/// A Block-Cipher Mode of Operation for Parallelizable Message Authentication
	/// </see>.
	/// </summary>
	public sealed class AesPmac : IMac
	{
		private const int BlockSize = Constants.BlockSize;
		private const int BufferSize = 4096;

		private readonly Aes aes;
		private readonly ICryptoTransform encryptor;
		private readonly byte[][] l = new byte[31][];
		private readonly byte[] inv;
		private readonly byte[] buffer = new byte[BufferSize];
		private readonly byte[] offset = new byte[BlockSize];
		private readonly byte[] sum = new byte[BlockSize];
		private uint counter;
		private int position;
		private bool disposed;

		/// <summary>
		/// Initializes a new instance of the <see cref="AesPmac"/> class with the specified key.
		/// </summary>
		/// <param name="key">The secret key for <see cref="AesPmac"> authentication.</param>
		public AesPmac(byte[] key)
		{
			if (key == null)
			{
				throw new ArgumentNullException(nameof(key));
			}

			aes = Utils.CreateAes(CipherMode.ECB);
			encryptor = aes.CreateEncryptor(key, null);

			byte[] temp = new byte[BlockSize];
			encryptor.TransformBlock(temp, 0, BlockSize, temp, 0);

			for (int i = 0; i < l.Length; ++i)
			{
				l[i] = (byte[])temp.Clone();
				Utils.Multiply(temp);
			}

			inv = (byte[])l[0].Clone();
			int lastBit = inv[BlockSize - 1] & 1;

			for (int i = BlockSize - 1; i > 0; --i)
			{
				int carry = Utils.ConstantTimeSelect(inv[i - 1] & 1, 0x80, 0);
				inv[i] = (byte)((inv[i] >> 1) | carry);
			}

			inv[0] >>= 1;
			inv[0] ^= (byte)Utils.ConstantTimeSelect(lastBit, 0x80, 0);
			inv[BlockSize - 1] ^= (byte)Utils.ConstantTimeSelect(lastBit, Constants.R >> 1, 0);
		}

		/// <summary>
		/// Adds more data to the running hash.
		/// </summary>
		/// <param name="input">The input to hash.</param>
		/// <param name="index">The offset into the input byte array from which to begin using data.</param>
		/// <param name="size">The number of bytes in the input byte array to use as data.</param>
		public void HashCore(byte[] input, int index, int size)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(AesCmac));
			}

			var seg = new ArraySegment<byte>(input, index, size);
			var left = BlockSize - position;

			if (position > 0 && seg.Count > left)
			{
				Array.Copy(seg.Array, seg.Offset, buffer, position, left);
				ProcessBuffer(BlockSize);
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
				Array.Copy(seg.Array, seg.Offset, buffer, position, count);
				ProcessBuffer(count);
				seg = seg.Slice(count);
			}

			if (seg.Count > 0)
			{
				Array.Copy(seg.Array, seg.Offset, buffer, position, seg.Count);
				position += seg.Count;
			}
		}

		/// <summary>
		/// Returns the current hash and resets the hash state.
		/// </summary>
		/// <returns>The value of the computed hash.</returns>
		public byte[] HashFinal()
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(AesCmac));
			}

			if (position == BlockSize)
			{
				Utils.Xor(buffer, sum, BlockSize);
				Utils.Xor(inv, sum, BlockSize);
			}
			else
			{
				Utils.Pad(buffer, position);
				Utils.Xor(buffer, sum, BlockSize);
			}

			byte[] result = encryptor.TransformFinalBlock(sum, 0, BlockSize);

			Array.Clear(offset, 0, BlockSize);
			Array.Clear(sum, 0, BlockSize);

			counter = 0;
			position = 0;

			return result;
		}

		private void ProcessBuffer(int size)
		{
			for (int i = 0; i < size; i += BlockSize)
			{
				int trailingZeros = Utils.TrailingZeros(counter + 1);

				Utils.Xor(l[trailingZeros], offset, BlockSize);
				Utils.Xor(offset, 0, buffer, i, BlockSize);

				++counter;
			}

			encryptor.TransformBlock(buffer, 0, size, buffer, 0);

			for (int i = 0; i < size; i += BlockSize)
			{
				Utils.Xor(buffer, i, sum, 0, BlockSize);
			}
		}

		public void Dispose()
		{
			if (!disposed)
			{
				aes.Dispose();
				encryptor.Dispose();

				Array.Clear(buffer, 0, BufferSize);
				Array.Clear(offset, 0, BlockSize);
				Array.Clear(sum, 0, BlockSize);

				disposed = true;
			}
		}
	}
}
