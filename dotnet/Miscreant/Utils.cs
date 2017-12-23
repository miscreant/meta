using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Miscreant
{
	internal static class Utils
	{
		private static readonly byte[] deBruijn = new byte[] {
			0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
			31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
		};

		private static readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

		public static ArraySegment<T> Slice<T>(this ArraySegment<T> seg, int index)
		{
			return new ArraySegment<T>(seg.Array, seg.Offset + index, seg.Count - index);
		}

		public static void Multiply(byte[] input)
		{
			Debug.Assert(input.Length == Constants.BlockSize);

			int carry = input[0] >> 7;

			for (int i = 0; i < Constants.BlockSize - 1; ++i)
			{
				input[i] = (byte)((input[i] << 1) | (input[i + 1] >> 7));
			}

			byte last = (byte)((input[Constants.BlockSize - 1] << 1) ^ ((0 - carry) & Constants.R));
			input[Constants.BlockSize - 1] = last;
		}

		public static void Xor(byte[] source, byte[] destination, int length)
		{
			Xor(source, 0, destination, 0, length);
		}

		public static void Xor(byte[] source, int sourceIndex, byte[] destination, int destinationIndex, int length)
		{
			for (int i = 0; i < length; ++i)
			{
				destination[destinationIndex + i] ^= source[sourceIndex + i];
			}
		}

		public static void Pad(byte[] buffer, int position)
		{
			buffer[position] = 0x80;

			for (int i = position + 1; i < Constants.BlockSize; ++i)
			{
				buffer[i] = 0;
			}
		}

		public static bool ConstantTimeEquals(byte[] x, byte[] y, int count)
		{
			byte result = 0;

			for (int i = 0; i < count; ++i)
			{
				result |= (byte)(x[i] ^ y[i]);
			}

			return result == 0;
		}

		/// <summary>
		/// ConstantTimeSelect returns x if v is 1 and y if v is 0.
		/// See <see href="https://golang.org/src/crypto/subtle/constant_time.go">constant_time.go</see> for more details.
		/// </summary>
		public static int ConstantTimeSelect(int v, int x, int y)
		{
			return ~(v - 1) & x | (v - 1) & y;
		}

		public static int Ceil(int dividend, int divisor)
		{
			return (dividend + divisor - 1) / divisor;
		}

		public static byte[] GetRandomBytes(int size)
		{
			var bytes = new byte[size];
			random.GetBytes(bytes);

			return bytes;
		}

		public static Aes CreateAes(CipherMode mode)
		{
			var aes = Aes.Create();

			aes.Mode = mode;
			aes.Padding = PaddingMode.None;

			return aes;
		}

		/// <summary>
		/// Count the number of trailing zeros bits in x.
		/// See <see href="https://golang.org/src/math/bits/bits.go">bits.go</see> for more details.
		/// </summary>
		public static int TrailingZeros(uint x)
		{
			return x > 0 ? deBruijn[(uint)((x & -x) * 0x077CB531) >> (32 - 5)] : 32;
		}
	}
}
