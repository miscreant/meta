using System;
using System.Security.Cryptography;

namespace Miscreant
{
	public sealed class StreamDecryptor : IDisposable
	{
		private readonly AesSiv siv;
		private readonly NonceEncoder nonce;
		private bool finished;
		private bool disposed;

		private StreamDecryptor(AesSiv siv, byte[] nonce)
		{
			this.siv = siv;
			this.nonce = new NonceEncoder(nonce);
		}

		public static StreamDecryptor CreateAesCmacSivDecryptor(byte[] key, byte[] nonce)
		{
			var siv = AesSiv.CreateAesCmacSiv(key);
			return new StreamDecryptor(siv, nonce);
		}

		public static StreamDecryptor CreateAesPmacSivDecryptor(byte[] key, byte[] nonce)
		{
			var siv = AesSiv.CreateAesPmacSiv(key);
			return new StreamDecryptor(siv, nonce);
		}

		public byte[] Open(byte[] plaintext, byte[] data = null, bool last = false)
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

			return siv.Open(plaintext, data, nonce.Next(last));
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
