using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Miscreant.Tests
{
	public class AesSivTest
	{
		[Fact]
		public void TestSealAndOpen()
		{
			foreach (var example in LoadExamples())
			{
				using (var siv = new AesSiv(example.Key))
				{
					byte[] ciphertext = siv.Seal(example.Plaintext, example.AssociatedData);
					Assert.Equal(Hex.Encode(example.Ciphertext), Hex.Encode(ciphertext));

					byte[] plaintext = siv.Open(ciphertext, example.AssociatedData);
					Assert.Equal(Hex.Encode(example.Plaintext), Hex.Encode(plaintext));
				}
			}
		}

		[Fact]
		public void TestTampering()
		{
			using (var siv = new AesSiv(new byte[32]))
			{
				// Test tag tampering

				var ciphertext = siv.Seal(new byte[0]);
				ciphertext[0] = 0;

				Assert.Throws<CryptographicException>(() => siv.Open(ciphertext));

				// Test ciphertext tampering

				ciphertext = siv.Seal(new byte[1]);
				ciphertext[ciphertext.Length - 1] = 0;

				Assert.Throws<CryptographicException>(() => siv.Open(ciphertext));

				// Test associated data tampering

				ciphertext = siv.Seal(new byte[0], new byte[] { 1 });

				Assert.Throws<CryptographicException>(() => siv.Open(ciphertext));
			}
		}

		[Fact]
		public void TestLargeMessage()
		{
			var key = new byte[32];
			var message = new byte[10000];
			var data = new byte[64];
			var tag = new byte[16];
			var last = new byte[16];

			using (var siv = new AesSiv(key))
			{
				var ciphertext = siv.Seal(message, data);

				Array.Copy(ciphertext, 0, tag, 0, 16);
				Array.Copy(ciphertext, message.Length, last, 0, 16);

				Assert.Equal("b6355f5f35349dcb5c9574443f7fe3f2", Hex.Encode(tag));
				Assert.Equal("46e332af8648f74f2d6375ff936b1fa3", Hex.Encode(last));
			}
		}

		[Fact]
		public void TestAuthenticationOnly()
		{
			var key = new byte[32];
			var data = new byte[64];
			var tag = "4cc0e8dee84dc6cd460e43acacb23cb4";

			using (var siv = new AesSiv(key))
			{
				Assert.Equal(tag, Hex.Encode(siv.Seal(new byte[0], data)));
				Assert.Equal(tag, Hex.Encode(siv.Seal(null, data)));
			}
		}

		private static IEnumerable<AesSivExample> LoadExamples()
		{
			var s = File.ReadAllText("../../../../../vectors/aes_siv.tjson");
			var json = JObject.Parse(s);
			var examples = json["examples:A<O>"];

			foreach (var example in examples)
			{
				var associatedData = new List<byte[]>();

				foreach (var item in (JArray)example["ad:A<d16>"])
				{
					associatedData.Add(Hex.Decode((string)item));
				}

				yield return new AesSivExample
				{
					Name = (string)example["name:s"],
					Key = Hex.Decode((string)example["key:d16"]),
					AssociatedData = associatedData.ToArray(),
					Plaintext = Hex.Decode((string)example["plaintext:d16"]),
					Ciphertext = Hex.Decode((string)example["ciphertext:d16"])
				};
			}
		}

		private struct AesSivExample
		{
			public string Name;
			public byte[] Key;
			public byte[][] AssociatedData;
			public byte[] Plaintext;
			public byte[] Ciphertext;
		}
	}
}
