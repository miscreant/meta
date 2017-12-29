using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Miscreant.Benchmarks
{
	[MemoryDiagnoser]
	public class AesSivBenchmark
	{
		private AesSiv cmacSiv;
		private AesSiv pmacSiv;
		private byte[] data;

		private byte[] message1K;
		private byte[] message8K;

		private byte[] ciphertextCmac1K;
		private byte[] ciphertextCmac8K;

		private byte[] ciphertextPmac1K;
		private byte[] ciphertextPmac8K;

		[GlobalSetup]
		public void Setup()
		{
			cmacSiv = AesSiv.CreateAesCmacSiv(new byte[32]);
			pmacSiv = AesSiv.CreateAesPmacSiv(new byte[32]);

			data = new byte[64];

			message1K = new byte[1024];
			message8K = new byte[8192];

			ciphertextCmac1K = cmacSiv.Seal(message1K, data);
			ciphertextCmac8K = cmacSiv.Seal(message8K, data);

			ciphertextPmac1K = pmacSiv.Seal(message1K, data);
			ciphertextPmac8K = pmacSiv.Seal(message8K, data);
		}

		[Benchmark]
		public void BenchmarkAesCmacSivSeal1K() => cmacSiv.Seal(message1K, data);

		[Benchmark]
		public void BenchmarkAesCmacSivSeal8K() => cmacSiv.Seal(message8K, data);

		[Benchmark]
		public void BenchmarkAesCmacSivOpen1K() => cmacSiv.Open(ciphertextCmac1K, data);

		[Benchmark]
		public void BenchmarkAesCmacSivOpen8K() => cmacSiv.Open(ciphertextCmac8K, data);

		[Benchmark]
		public void BenchmarkAesPmacSivSeal1K() => pmacSiv.Seal(message1K, data);

		[Benchmark]
		public void BenchmarkAesPmacSivSeal8K() => pmacSiv.Seal(message8K, data);

		[Benchmark]
		public void BenchmarkAesPmacSivOpen1K() => pmacSiv.Open(ciphertextPmac1K, data);

		[Benchmark]
		public void BenchmarkAesPmacSivOpen8K() => pmacSiv.Open(ciphertextPmac8K, data);
	}
}
