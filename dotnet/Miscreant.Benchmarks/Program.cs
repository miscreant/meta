using BenchmarkDotNet.Running;

namespace Miscreant.Benchmarks
{
	public class Program
	{
		public static void Main(string[] args)
		{
			BenchmarkRunner.Run<AesCmacBenchmark>();
		}
	}
}
