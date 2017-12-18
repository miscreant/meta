using System;
using System.Diagnostics;

namespace Miscreant
{
	internal static class Utils
	{
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

			byte last = (byte)((input[Constants.BlockSize - 1] << 1) ^ ((0 - carry) & 0x87));
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
	}
}
