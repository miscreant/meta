using System;
using System.Security.Cryptography;

namespace Miscreant
{
	public sealed class AesSiv : IDisposable
	{
		private const int BlockSize = Constants.BlockSize;
		private static readonly byte[] Zero = new byte[BlockSize];

		private readonly KeyedHashAlgorithm mac;
		private bool disposed;

		private AesSiv(byte[] key)
		{
			mac = new AesCmac(key);
		}

		/// <summary>
		/// S2V operation, defined in the section 2.4 of
		/// <see href="https://tools.ietf.org/html/rfc5297#section-2.4">RFC 5297</see>.
		/// </summary>
		private byte[] S2V(byte[][] headers, byte[] message)
		{
			if (headers == null)
			{
				throw new ArgumentNullException(nameof(headers));
			}

			if (message == null)
			{
				throw new ArgumentNullException(nameof(message));
			}

			// The standalone S2V returns CMAC(1) if the number of
			// passed vectors is zero, however in SIV contruction
			// this case is never triggered, since we always pass
			// plaintext as the last vector (even if it's zero-length),
			// so we omit this case.

			mac.TransformFinalBlock(Zero, 0, BlockSize);
			byte[] v = mac.Hash;

			foreach (var header in headers)
			{
				if (header == null)
				{
					throw new ArgumentNullException(nameof(header));
				}

				mac.TransformFinalBlock(header, 0, header.Length);
				Utils.Multiply(v);
				Utils.Xor(mac.Hash, v, BlockSize);
			}

			if (message.Length > BlockSize)
			{
				int n = message.Length - BlockSize;

				mac.TransformBlock(message, 0, n, message, 0);
				Utils.Xor(message, n, v, 0, BlockSize);
				mac.TransformFinalBlock(v, 0, BlockSize);

				return mac.Hash;
			}

			byte[] padded = (byte[])message.Clone();

			Utils.Multiply(v);
			Utils.Pad(padded, message.Length);
			Utils.Xor(padded, v, BlockSize);
			mac.TransformFinalBlock(v, 0, BlockSize);

			return mac.Hash;
		}

		public void Dispose()
		{
			if (!disposed)
			{
				mac.Dispose();
				disposed = true;
			}
		}
	}
}
