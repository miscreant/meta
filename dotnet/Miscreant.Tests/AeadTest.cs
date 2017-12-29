using System;
using System.Collections.Generic;
using System.IO;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Miscreant.Tests
{
	public class AeadTest
	{
		[Fact]
		public void TestSealAndOpen()
		{
			foreach (var example in LoadExamples())
			{
				using (var aead = CreateAead(example.Algorithm, example.Key))
				{
					var ciphertext = aead.Seal(example.Plaintext, example.Nonce, example.AssociatedData);
					Assert.Equal(Hex.Encode(example.Ciphertext), Hex.Encode(ciphertext));

					var plaintext = aead.Open(example.Ciphertext, example.Nonce, example.AssociatedData);
					Assert.Equal(Hex.Encode(example.Plaintext), Hex.Encode(plaintext));
				}
			}
		}

		private static IEnumerable<AeadExample> LoadExamples()
		{
			var s = File.ReadAllText($"../../../../../vectors/aes_siv_aead.tjson");
			var json = JObject.Parse(s);
			var examples = json["examples:A<O>"];

			foreach (var example in examples)
			{
				yield return new AeadExample
				{
					Name = (string)example["name:s"],
					Algorithm = (string)example["alg:s"],
					Key = Hex.Decode((string)example["key:d16"]),
					AssociatedData = Hex.Decode((string)example["ad:d16"]),
					Nonce = Hex.Decode((string)example["nonce:d16"]),
					Plaintext = Hex.Decode((string)example["plaintext:d16"]),
					Ciphertext = Hex.Decode((string)example["ciphertext:d16"])
				};
			}
		}

		private static Aead CreateAead(string algorithm, byte[] key)
		{
			switch (algorithm)
			{
				case "AES-SIV": return Aead.CreateAesCmacSiv(key);
				case "AES-PMAC-SIV": return Aead.CreateAesPmacSiv(key);
				default: throw new ArgumentException("Unknown algorithm.");
			}
		}

		private struct AeadExample
		{
			public string Name;
			public string Algorithm;
			public byte[] Key;
			public byte[] AssociatedData;
			public byte[] Nonce;
			public byte[] Plaintext;
			public byte[] Ciphertext;
		}
	}
}
