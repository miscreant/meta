using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Miscreant.Tests
{
	public class AesCtrTest
	{
		[Fact]
		public void TestEncrypt()
		{
			foreach (var example in LoadExamples())
			{
				var key = Hex.Decode(example.Key);
				var iv = Hex.Decode(example.Iv);
				var plaintext = Hex.Decode(example.Plaintext);

				using (var ctr = new AesCtr(key, iv))
				{
					ctr.Encrypt(plaintext, 0, plaintext.Length, plaintext, 0);
					Assert.Equal(example.Ciphertext, Hex.Encode(plaintext));
				}
			}
		}

		[Fact]
		public void TestLargeMessage()
		{
			var key = new byte[16];
			var iv = new byte[16];
			var message = new byte[10000];
			var last = new byte[16];
			var expected = "3b9a44f22bb1522f10c00ff8ca5195ea";

			// Test encrypting the whole message

			using (var ctr = new AesCtr(key, iv))
			{
				ctr.Encrypt(message, 0, message.Length, message, 0);
				Array.Copy(message, message.Length - last.Length, last, 0, last.Length);
				Assert.Equal(expected, Hex.Encode(last));
			}

			// Test encrypting the message in chunks

			using (var ctr = new AesCtr(key, iv))
			{
				Array.Clear(message, 0, message.Length);

				var seg = new ArraySegment<byte>(message);
				var chunkSize = 137;

				while (seg.Count > 0)
				{
					ctr.Encrypt(seg.Array, seg.Offset, seg.Count, message, 0);
					seg = seg.Slice(Math.Min(seg.Count, chunkSize));
				}

				Array.Copy(message, message.Length - last.Length, last, 0, last.Length);
				Assert.Equal(expected, Hex.Encode(last));
			}
		}

		private static IEnumerable<(string Key, string Iv, string Plaintext, string Ciphertext)> LoadExamples()
		{
			var s = File.ReadAllText("../../../../../vectors/aes_ctr.tjson");
			var json = JObject.Parse(s);
			var examples = json["examples:A<O>"];

			foreach (var example in examples)
			{
				string key = (string)example["key:d16"];
				string iv = (string)example["iv:d16"];
				string plaintext = (string)example["plaintext:d16"];
				string ciphertext = (string)example["ciphertext:d16"];

				yield return (key, iv, plaintext, ciphertext);
			}
		}
	}
}
