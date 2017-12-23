using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Miscreant.Benchmarks
{
	[MemoryDiagnoser]
	public class SivBenchmark
	{
		private AesSiv siv;
		private byte[] data;

		private byte[] message1K;
		private byte[] message8K;

		private byte[] ciphertext1K;
		private byte[] ciphertext8K;

		[GlobalSetup]
		public void Setup()
		{
			siv = new AesSiv(new byte[32]);
			data = new byte[64];

			message1K = new byte[1024];
			message8K = new byte[8192];

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
