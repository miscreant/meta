using System;

namespace Miscreant.Tests
{
	internal static class Hex
	{
		public static string Encode(byte[] raw)
		{
			return BitConverter.ToString(raw).Replace("-", String.Empty).ToLowerInvariant();
		}

		public static byte[] Decode(string hex)
		{
			byte[] raw = new byte[hex.Length / 2];

			for (int i = 0; i < raw.Length; ++i)
			{
				raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
			}

			return raw;
		}
	}
}
