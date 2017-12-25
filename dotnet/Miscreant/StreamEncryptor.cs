using System;
using System.Security.Cryptography;

namespace Miscreant
{
	public sealed class StreamEncryptor : IDisposable
	{
		private readonly AesSiv siv;
		private readonly NonceEncoder nonce;
		private bool finished;
		private bool disposed;

		private StreamEncryptor(AesSiv siv, byte[] nonce)
		{
			this.siv = siv;
			this.nonce = new NonceEncoder(nonce);
		}

		public static StreamEncryptor CreateAesCmacSivEncryptor(byte[] key, byte[] nonce)
		{
			var siv = AesSiv.CreateAesCmacSiv(key);
			return new StreamEncryptor(siv, nonce);
		}

		public static StreamEncryptor CreateAesPmacSivEncryptor(byte[] key, byte[] nonce)
		{
			var siv = AesSiv.CreateAesPmacSiv(key);
			return new StreamEncryptor(siv, nonce);
		}

		public byte[] Seal(byte[] plaintext, byte[] data = null, bool last = false)
		{
			if (disposed)
			{
				throw new ObjectDisposedException(nameof(StreamEncryptor));
			}

			if (finished)
			{
				throw new CryptographicException("STREAM is already finished.");
			}

			finished = last;

			return siv.Seal(plaintext, data, nonce.Next(last));
		}

		public void Dispose()
		{
			if (!disposed)
			{
				siv.Dispose();
				disposed = true;
			}
		}
	}
}
