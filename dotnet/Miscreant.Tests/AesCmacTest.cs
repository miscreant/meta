using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Miscreant.Tests
{
	public class AesCmacTest
	{
		private readonly List<(string Key, string Message, string Tag)> examples = LoadExamples().ToList();

		[Fact]
		public void TestHashFinal()
		{
			foreach (var example in examples)
			{
				var key = Hex.Decode(example.Key);
				var message = Hex.Decode(example.Message);

				using (var cmac = new AesCmac(key))
				{
					cmac.HashCore(message, 0, message.Length);
					Assert.Equal(example.Tag, Hex.Encode(cmac.HashFinal()));
				}
			}
		}

		[Fact]
		public void TestHashCore()
		{
			var example = examples.Last();
			var key = Hex.Decode(example.Key);
			var message = Hex.Decode(example.Message);
			var cmac = new AesCmac(key);

			// Test writing byte-by-byte

			for (int i = 0; i < message.Length; ++i)
			{
				cmac.HashCore(message, i, 1);
			}

			Assert.Equal(example.Tag, Hex.Encode(cmac.HashFinal()));

			// Test writing halves

			int half = message.Length / 2;

			cmac.HashCore(message, 0, half);
			cmac.HashCore(message, half, message.Length - half);

			Assert.Equal(example.Tag, Hex.Encode(cmac.HashFinal()));

			// Test writing third, then the rest

			int third = message.Length / 3;

			cmac.HashCore(message, 0, third);
			cmac.HashCore(message, third, message.Length - third);

			Assert.Equal(example.Tag, Hex.Encode(cmac.HashFinal()));
		}

		[Fact]
		public void TestLargeMessage()
		{
			var key = new byte[16];
			var message = new byte[10000];
			var cmac = new AesCmac(key);

			cmac.HashCore(message, 0, message.Length);
			Assert.Equal("994d0e70cfa12cb68023cbdfa11cbd81", Hex.Encode(cmac.HashFinal()));
		}

		private static IEnumerable<(string Key, string Message, string Tag)> LoadExamples()
		{
			var s = File.ReadAllText("../../../../../vectors/aes_cmac.tjson");
			var json = JObject.Parse(s);
			var examples = json["examples:A<O>"];

			foreach (var example in examples)
			{
				string key = (string)example["key:d16"];
				string message = (string)example["message:d16"];
				string tag = (string)example["tag:d16"];

				yield return (key, message, tag);
			}
		}
	}
}
