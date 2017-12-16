using System.Diagnostics;

namespace Miscreant
{
	internal static class Utils
	{
		private const int BlockSize = 16;

		public static void Multiply(byte[] input)
		{
			Debug.Assert(input.Length == BlockSize);

			int carry = input[0] >> 7;

			for (int i = 0; i < BlockSize - 1; ++i)
			{
				input[i] = (byte)((input[i] << 1) | (input[i + 1] >> 7));
			}

			input[BlockSize - 1] = (byte)((input[BlockSize - 1] << 1) ^ ((0 - carry) & 0x87));
		}

		public static void Xor(byte[] source, byte[] destination, int length)
		{
			for (int i = 0; i < length; ++i)
			{
				destination[i] ^= source[i];
			}
		}
	}
}
