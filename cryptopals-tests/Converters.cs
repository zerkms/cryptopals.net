using NUnit.Framework;
using Cryptopals;

namespace cryptopals_tests
{
    class ConvertersTest
    {
        [Test]
        public void HexToBytes()
        {
            var source = "00A00F";

            var actual = Converters.HexToBytes(source);
            var expected = new byte[] { 0x00, 0xA0, 0x0F };

            Assert.AreEqual(expected, actual);
        }
    }
}
