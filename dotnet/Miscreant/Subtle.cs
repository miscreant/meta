using System.Runtime.CompilerServices;

namespace Miscreant
{
	internal static class Subtle
	{
		[MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
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
		[MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
		public static int ConstantTimeSelect(int v, int x, int y)
		{
			return ~(v - 1) & x | (v - 1) & y;
		}
	}
}
