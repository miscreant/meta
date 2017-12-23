using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Miscreant.Tests
{
	public class MacTest
	{
		private readonly List<MacExample> cmacExamples = LoadExamples("aes_cmac").ToList();
		private readonly List<MacExample> pmacExamples = LoadExamples("aes_pmac").ToList();

		[Fact]
		public void TestCmacHashFinal() => TestHashFinal(AesCmac.Create, cmacExamples);

		[Fact]
		public void TestPmacHashFinal() => TestHashFinal(AesPmac.Create, pmacExamples);

		private void TestHashFinal(Func<byte[], IMac> macFactory, IEnumerable<MacExample> examples)
		{
			foreach (var example in examples)
			{
				var key = Hex.Decode(example.Key);
				var message = Hex.Decode(example.Message);

				using (var mac = macFactory(key))
				{
					mac.HashCore(message, 0, message.Length);
					Assert.Equal(example.Tag, Hex.Encode(mac.HashFinal()));
				}
			}
		}

		[Fact]
		public void TestCmacHashCore() => TestHashCore(AesCmac.Create, cmacExamples);

		[Fact]
		public void TestPmacHashCore() => TestHashCore(AesPmac.Create, pmacExamples);

		private void TestHashCore(Func<byte[], IMac> macFactory, IEnumerable<MacExample> examples)
		{
			var example = examples.Last();
			var key = Hex.Decode(example.Key);
			var message = Hex.Decode(example.Message);

			using (var mac = macFactory(key))
			{
				// Test writing byte-by-byte

				for (int i = 0; i < message.Length; ++i)
				{
					mac.HashCore(message, i, 1);
				}

				Assert.Equal(example.Tag, Hex.Encode(mac.HashFinal()));

				// Test writing halves

				int half = message.Length / 2;

				mac.HashCore(message, 0, half);
				mac.HashCore(message, half, message.Length - half);

				Assert.Equal(example.Tag, Hex.Encode(mac.HashFinal()));

				// Test writing third, then the rest

				int third = message.Length / 3;

				mac.HashCore(message, 0, third);
				mac.HashCore(message, third, message.Length - third);

				Assert.Equal(example.Tag, Hex.Encode(mac.HashFinal()));
			}
		}

		[Fact]
		public void TestLargeMessage()
		{
			var key = new byte[16];
			var message = new byte[10000];

			using (var cmac = new AesCmac(key))
			{
				cmac.HashCore(message, 0, message.Length);
				Assert.Equal("994d0e70cfa12cb68023cbdfa11cbd81", Hex.Encode(cmac.HashFinal()));
			}

			using (var pmac = new AesPmac(key))
			{
				pmac.HashCore(message, 0, message.Length);
				Assert.Equal("823a7d32a9d5ee2e8667ee02ab08e511", Hex.Encode(pmac.HashFinal()));
			}
		}

		private static IEnumerable<MacExample> LoadExamples(string file)
		{
			var s = File.ReadAllText($"../../../../../vectors/{file}.tjson");
			var json = JObject.Parse(s);
			var examples = json["examples:A<O>"];

			foreach (var example in examples)
			{
				yield return new MacExample
				{
					Key = (string)example["key:d16"],
					Message = (string)example["message:d16"],
					Tag = (string)example["tag:d16"]
				};
			}
		}

		private struct MacExample
		{
			public string Key;
			public string Message;
			public string Tag;
		}
	}
}
