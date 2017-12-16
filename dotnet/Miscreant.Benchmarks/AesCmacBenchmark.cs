using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Miscreant.Benchmarks
{
	[MemoryDiagnoser]
	public class AesCmacBenchmark
	{
		private const int BlockSize = 16;
		private const int MessageSize = 1024;

		private static readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

		private readonly byte[] message;
		private readonly AesCmac cmac;
		private readonly ICryptoTransform encryptor;

		public AesCmacBenchmark()
		{
			var key = GetRandomBytes(BlockSize);
			var iv = GetRandomBytes(BlockSize);

			message = GetRandomBytes(MessageSize);
			cmac = new AesCmac(key);

			var aes = Aes.Create();
			aes.Mode = CipherMode.CBC;

			encryptor = aes.CreateEncryptor(key, iv);
		}

		[Benchmark]
		public void BenchmarkAesCmac()
		{
			cmac.TransformBlock(message, 0, message.Length, message, 0);
		}

		[Benchmark]
		public void BenchmarkAes()
		{
			encryptor.TransformBlock(message, 0, message.Length, message, 0);
		}

		private static byte[] GetRandomBytes(int size)
		{
			var bytes = new byte[size];
			random.GetBytes(bytes);

			return bytes;
		}
	}
}
