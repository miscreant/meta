using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Miscreant.Benchmarks
{
	[MemoryDiagnoser]
	public class MacBenchmark
	{
		private const int BlockSize = 16;
		private const int MessageSize = 1024;
		private static readonly RandomNumberGenerator random = RandomNumberGenerator.Create();

		private readonly byte[] message;
		private readonly AesCmac cmac;
		private readonly AesPmac pmac;
		private readonly ICryptoTransform encryptor;

		public MacBenchmark()
		{
			var key = Utils.GetRandomBytes(BlockSize);
			var iv = Utils.GetRandomBytes(BlockSize);

			message = Utils.GetRandomBytes(MessageSize);
			cmac = new AesCmac(key);
			pmac = new AesPmac(key);

			var aes = Aes.Create();
			aes.Mode = CipherMode.CBC;

			encryptor = aes.CreateEncryptor(key, iv);
		}

		[Benchmark]
		public void BenchmarkAesCmac() => cmac.HashCore(message, 0, message.Length);

		[Benchmark]
		public void BenchmarkAesPmac() => pmac.HashCore(message, 0, message.Length);

		[Benchmark]
		public void BenchmarkAes() => encryptor.TransformBlock(message, 0, message.Length, message, 0);
	}
}
