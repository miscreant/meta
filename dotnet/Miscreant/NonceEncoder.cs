using System;
using System.Security.Cryptography;

namespace Miscreant
{
	internal class NonceEncoder
	{
		private const int NonceSize = 8;
		private const int CounterSize = 4;

		private readonly byte[] nonce;
		private uint counter;

		public NonceEncoder(byte[] nonce)
		{
			if (nonce == null)
			{
				throw new ArgumentNullException(nameof(nonce));
			}

			if (nonce.Length != NonceSize)
			{
				throw new CryptographicException("Specified nonce does not match the nonce size for this algorithm.");
			}

			this.nonce = new byte[NonceSize + CounterSize + 1];
			Array.Copy(nonce, this.nonce, NonceSize);
		}

		public byte[] Next(bool last)
		{
			nonce[NonceSize] = (byte)((counter >> 24) & 0xff);
			nonce[NonceSize + 1] = (byte)((counter >> 16) & 0xff);
			nonce[NonceSize + 2] = (byte)((counter >> 8) & 0xff);
			nonce[NonceSize + 3] = (byte)(counter & 0xff);

			if (last)
			{
				nonce[nonce.Length - 1] = 1;
			}

			try
			{
				checked
				{
					++counter;
				}
			}
			catch (OverflowException ex)
			{
				throw new CryptographicException("STREAM counter overflowed.", ex);
			}

			return nonce;
		}
	}
}
