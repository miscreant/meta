using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Miscreant.Tests
{
	public class UtilsTest
	{
		[Fact]
		public void TestMultiply()
		{
			foreach (var example in LoadExamples())
			{
				var input = Hex.Decode(example.Input);
				Utils.Multiply(input);

				Assert.Equal(example.Output, Hex.Encode(input));
			}
		}

		private static IEnumerable<(string Input, string Output)> LoadExamples()
		{
			var s = File.ReadAllText("../../../../../vectors/dbl.tjson");
			var json = JObject.Parse(s);
			var examples = json["examples:A<O>"];

			foreach (var example in examples)
			{
				string input = (string)example["input:d16"];
				string output = (string)example["output:d16"];

				yield return (input, output);
			}
		}
	}
}
