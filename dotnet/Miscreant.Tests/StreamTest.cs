using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Miscreant.Tests
{
	public class StreamTest
	{
		[Fact]
		public void TestSealAndOpen()
		{
			foreach (var example in LoadExamples())
			{
				using (var encryptor = CreateEncryptor(example.Algorithm, example.Key, example.Nonce))
				using (var decryptor = CreateDecryptor(example.Algorithm, example.Key, example.Nonce))
				{
					for (int i = 0; i < example.Blocks.Length; ++i)
					{
						var block = example.Blocks[i];
						var last = i == example.Blocks.Length - 1;

						var ciphertext = encryptor.Seal(block.Plaintext, block.AssociatedData, last);
						var plaintext = decryptor.Open(block.Ciphertext, block.AssociatedData, last);

						Assert.Equal(Hex.Encode(block.Ciphertext), Hex.Encode(ciphertext));
						Assert.Equal(Hex.Encode(block.Plaintext), Hex.Encode(plaintext));
					}
				}
			}
		}

		private static IEnumerable<StreamExample> LoadExamples()
		{
			var s = File.ReadAllText($"../../../../../vectors/aes_siv_stream.tjson");
			var json = JObject.Parse(s);
			var examples = json["examples:A<O>"];

			foreach (var example in examples)
			{
				var blocks = new List<Block>();

				foreach (var item in (JArray)example["blocks:A<O>"])
				{
					blocks.Add(new Block
					{
						AssociatedData = Hex.Decode((string)item["ad:d16"]),
						Plaintext = Hex.Decode((string)item["plaintext:d16"]),
						Ciphertext = Hex.Decode((string)item["ciphertext:d16"])
					});
				}

				yield return new StreamExample
				{
					Name = (string)example["name:s"],
					Algorithm = (string)example["alg:s"],
					Key = Hex.Decode((string)example["key:d16"]),
					Nonce = Hex.Decode((string)example["nonce:d16"]),
					Blocks = blocks.ToArray()
				};
			}
		}

		private static StreamEncryptor CreateEncryptor(string algorithm, byte[] key, byte[] nonce)
		{
			switch (algorithm)
			{
				case "AES-SIV": return StreamEncryptor.CreateAesCmacSivEncryptor(key, nonce);
				case "AES-PMAC-SIV": return StreamEncryptor.CreateAesPmacSivEncryptor(key, nonce);
				default: throw new ArgumentException("Unknown algorithm.");
			}
		}

		private static StreamDecryptor CreateDecryptor(string algorithm, byte[] key, byte[] nonce)
		{
			switch (algorithm)
			{
				case "AES-SIV": return StreamDecryptor.CreateAesCmacSivDecryptor(key, nonce);
				case "AES-PMAC-SIV": return StreamDecryptor.CreateAesPmacSivDecryptor(key, nonce);
				default: throw new ArgumentException("Unknown algorithm.");
			}
		}

		private struct StreamExample
		{
			public string Name;
			public string Algorithm;
			public byte[] Key;
			public byte[] Nonce;
			public Block[] Blocks;
		}

		private struct Block
		{
			public byte[] AssociatedData;
			public byte[] Plaintext;
			public byte[] Ciphertext;
		}
	}
}
