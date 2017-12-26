using System;
using System.Collections.Generic;
using System.Text;

namespace Miscreant.Examples
{
	public class Program
	{
		public static void Main(string[] args)
		{
			StreamExample();
		}

		private static void AeadExample()
		{
			// Plaintext to encrypt.
			var plaintext = "I'm cooking MC's like a pound of bacon";

			// Create a 32-byte key.
			var key = Aead.GenerateKey256();

			// Create a 16-byte nonce (optional).
			var nonce = Aead.GenerateNonce(16);

			// Create a new AEAD instance using the AES-CMAC-SIV
			// algorithm. It implements the IDisposable interface,
			// so it's best to create it inside using statement.
			using (var aead = Aead.CreateAesCmacSiv(key))
			{
				// If the message is string, convert it to byte array first.
				var bytes = Encoding.UTF8.GetBytes(plaintext);

				// Encrypt the message.
				var ciphertext = aead.Seal(bytes, nonce);

				// To decrypt the message, call the Open method with the
				// ciphertext and the same nonce that you generated previously.
				bytes = aead.Open(ciphertext, nonce);

				// If the message was originally string,
				// convert if from byte array to string.
				plaintext = Encoding.UTF8.GetString(bytes);

				// Print the decrypted message to the standard output.
				Console.WriteLine(plaintext);
			}
		}

		private static void StreamExample()
		{
			// Messages to encrypt.
			var messages = new List<string> {
				"Now that the party is jumping",
				"With the bass kicked in, the fingers are pumpin'",
				"Quick to the point, to the point no faking",
				"I'm cooking MC's like a pound of bacon"
			};

			// Create a 32-byte key.
			var key = Aead.GenerateKey256();

			// Create a 8-byte STREAM nonce (required).
			var nonce = StreamEncryptor.GenerateNonce();

			// Create STREAM encryptor and decryptor using the AES-CMAC-SIV
			// algorithm. They implement the IDisposable interface,
			// so it's best to create them inside using statement.
			using (var encryptor = StreamEncryptor.CreateAesCmacSivEncryptor(key, nonce))
			using (var decryptor = StreamDecryptor.CreateAesCmacSivDecryptor(key, nonce))
			{
				for (int i = 0; i < messages.Count; ++i)
				{
					// Calculate whether the message is the last message to encrypt.
					bool last = i == messages.Count - 1;

					// Convert the message to byte array first.
					var bytes = Encoding.UTF8.GetBytes(messages[i]);

					// Encrypt the message.
					var ciphertext = encryptor.Seal(bytes, null, last);

					// Decrypt the message.
					var message = decryptor.Open(ciphertext, null, last);

					// Convert the message back to string.
					var plaintext = Encoding.UTF8.GetString(bytes);

					// Print the decrypted message to the standard output.
					Console.WriteLine(plaintext);
				}
			}
		}
	}
}
