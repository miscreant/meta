using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Miscreant.Benchmarks
{
	[MemoryDiagnoser]
	public class AesSivBenchmark
	{
		private readonly AesSiv siv = new AesSiv(new byte[32]);
		private readonly byte[] data = new byte[64];

		private readonly byte[] message1K = new byte[1024];
		private readonly byte[] message8K = new byte[8192];

		private readonly byte[] ciphertext1K;
		private readonly byte[] ciphertext8K;

		public AesSivBenchmark()
		{
			ciphertext1K = siv.Seal(message1K, data);
			ciphertext8K = siv.Seal(message8K, data);
		}

		[Benchmark]
		public void BenchmarkAesSivSeal1K() => siv.Seal(message1K, data);

		[Benchmark]
		public void BenchmarkAesSivSeal8K() => siv.Seal(message8K, data);

		[Benchmark]
		public void BenchmarkAesSivOpen1K() => siv.Open(ciphertext1K, data);

		[Benchmark]
		public void BenchmarkAesSivOpen8K() => siv.Open(ciphertext8K, data);
	}
}
