using System;

namespace Miscreant
{
	/// <summary>
	/// Defines the basic operations of message authentication code.
	/// </summary>
	public interface IMac : IDisposable
	{
		/// <summary>
		/// Adds more data to the running hash.
		/// </summary>
		/// <param name="input">The input to hash.</param>
		/// <param name="index">The offset into the input byte array from which to begin using data.</param>
		/// <param name="size">The number of bytes in the input byte array to use as data.</param>
		void HashCore(byte[] input, int index, int size);

		/// <summary>
		/// Returns the current hash and resets the hash state.
		/// </summary>
		/// <returns>The value of the computed hash.</returns>
		byte[] HashFinal();
	}
}
