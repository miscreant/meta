namespace Miscreant
{
	internal static class Utils
	{
		private const int BlockSize = 16;

		public static byte[] Multiply(byte[] input)
		{
			byte[] output = new byte[BlockSize];

			for (int i = 0; i < BlockSize - 1; ++i)
			{
				output[i] = (byte)((input[i] << 1) | (input[i + 1] >> 7));
			}

			int carry = input[0] >> 7;
			output[BlockSize - 1] = (byte)((input[BlockSize - 1] << 1) ^ ((0 - carry) & 0x87));

			return output;
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
