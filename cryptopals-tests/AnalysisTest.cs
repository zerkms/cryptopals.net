using System.Linq;
using NUnit.Framework;
using Cryptopals;
using System.Diagnostics.Contracts;

namespace cryptopals_tests
{
    class AnalysisTest
    {
        [Test]
        public void ScorerTest()
        {
            var hello = Analysis.Score("Hello");
            var gibberish = Analysis.Score("..z!!!!!!!!!");

            Assert.Greater(hello, gibberish);
        }

        [Test]
        public void HammingDistanceTest()
        {
            var a = "this is a test";
            var b = "wokka wokka!!!";

            var expected = 37;
            var actual = Analysis.HammingDistance(Converters.StringToBytes(a), Converters.StringToBytes(b));

            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void WightedHammingDistanceTest()
        {
            var a = Converters.StringToBytes("this is a test");
            var b = Converters.StringToBytes("wokka wokka!!!");

            var expected = 2.642857;

            Contract.Assume(a.Length > 0);
            var actual = Analysis.WeightedHammingDistance(a, b);

            Assert.AreEqual(expected, actual, 0.00001);
        }

        [Test]
        public void FindKeyLengthTest()
        {
            var message = "Hello World this is a test message";
            var key = new byte[] { 0x11, 0x42, 0x18, 0xA9, 0x0F };
            var encrypted = Encryption.RepeatedXor(key, Converters.StringToBytes(message));
            var keyLength = 10;

            Contract.Assume(encrypted.Length >= keyLength * 3);
            var result = Analysis.FindKeyLength(encrypted, keyLength);

            var lengths = result.Take(3).Select(kl => kl.Length);

            Assert.IsTrue(lengths.Contains(key.Length));
        }
    }
}
