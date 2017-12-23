using System;
using System.Text;

namespace Miscreant.Examples
{
	public class Program
	{
		public static void Main(string[] args)
		{
			// Plaintext to encrypt.
			var plaintext = "I'm cooking MC's like a pound of bacon";

			// Create a 32-byte key.
			var key = AesSiv.GenerateKey256();

			// Create a 16-byte nonce (optional).
			var nonce = AesSiv.GenerateNonce(16);

			// Create a new AES-CMAC-SIV instance. It implements the IDisposable
			// interface, so it's best to create it inside using statement.
			using (var siv = AesSiv.CreateAesCmacSiv(key))
			{
				// If the message is string, convert it to byte array first.
				var bytes = Encoding.UTF8.GetBytes(plaintext);

				// Encrypt the message.
				var ciphertext = siv.Seal(bytes, nonce);

				// To decrypt the message, call the Open method with the
				// ciphertext and the same nonce that you generated previously.
				bytes = siv.Open(ciphertext, nonce);

				// If the message was originally string,
				// convert if from byte array to string.
				plaintext = Encoding.UTF8.GetString(bytes);

				// Print the decrypted message to the standard output.
				Console.WriteLine(plaintext);
			}
		}
	}
}
