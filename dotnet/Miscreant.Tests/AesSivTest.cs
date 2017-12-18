using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
