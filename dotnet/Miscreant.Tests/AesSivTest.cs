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
		public void TestCmacSealAndOpen() => TestSealAndOpen(AesSiv.CreateAesCmacSiv, "aes_siv");

		[Fact]
		public void TestPmacSealAndOpen() => TestSealAndOpen(AesSiv.CreateAesPmacSiv, "aes_pmac_siv");

		private void TestSealAndOpen(Func<byte[], AesSiv> sivFactory, string file)
		{
			foreach (var example in LoadExamples(file))
			{
				using (var siv = sivFactory(example.Key))
				{
					byte[] ciphertext = siv.Seal(example.Plaintext, example.AssociatedData);
					Assert.Equal(Hex.Encode(example.Ciphertext), Hex.Encode(ciphertext));

					byte[] plaintext = siv.Open(ciphertext, example.AssociatedData);
					Assert.Equal(Hex.Encode(example.Plaintext), Hex.Encode(plaintext));
				}
			}
		}

		[Fact]
		public void TestCmacTampering() => TestTampering(AesSiv.CreateAesCmacSiv);

		[Fact]
		public void TestPmacTampering() => TestTampering(AesSiv.CreateAesPmacSiv);

		private void TestTampering(Func<byte[], AesSiv> sivFactory)
		{
			using (var siv = sivFactory(new byte[32]))
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
		public void TestCmacLargeMessage() => TestLargeMessage(
			AesSiv.CreateAesCmacSiv,
			"b6355f5f35349dcb5c9574443f7fe3f2",
			"46e332af8648f74f2d6375ff936b1fa3"
		);

		[Fact]
		public void TestPmacLargeMessage() => TestLargeMessage(
			AesSiv.CreateAesPmacSiv,
			"fa7a298c6c3668b27258cff211c6eaf4",
			"79895a27a8d7a17c416cbf3a3a7c38ee"
		);

		private void TestLargeMessage(Func<byte[], AesSiv> sivFactory, string firstBlock, string lastBlock)
		{
			var key = new byte[32];
			var message = new byte[10000];
			var data = new byte[64];
			var tag = new byte[16];
			var last = new byte[16];

			using (var siv = sivFactory(key))
			{
				var ciphertext = siv.Seal(message, data);

				Array.Copy(ciphertext, 0, tag, 0, 16);
				Array.Copy(ciphertext, message.Length, last, 0, 16);

				Assert.Equal(firstBlock, Hex.Encode(tag));
				Assert.Equal(lastBlock, Hex.Encode(last));
			}
		}

		[Fact]
		public void TestCmacAuthenticationOnly() => TestAuthenticationOnly(
			AesSiv.CreateAesCmacSiv,
			"4cc0e8dee84dc6cd460e43acacb23cb4"
		);

		[Fact]
		public void TestPmacAuthenticationOnly() => TestAuthenticationOnly(
			AesSiv.CreateAesPmacSiv,
			"ba087cb5d41830ba65d92b5ce71dc129"
		);

		private void TestAuthenticationOnly(Func<byte[], AesSiv> sivFactory, string tag)
		{
			var key = new byte[32];
			var data = new byte[64];

			using (var siv = sivFactory(key))
			{
				Assert.Equal(tag, Hex.Encode(siv.Seal(new byte[0], data)));
				Assert.Equal(tag, Hex.Encode(siv.Seal(null, data)));
			}
		}

		private static IEnumerable<AesSivExample> LoadExamples(string file)
		{
			var s = File.ReadAllText($"../../../../../vectors/{file}.tjson");
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
