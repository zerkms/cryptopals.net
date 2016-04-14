using System;
using System.Text;
using System.Linq;
using System.Diagnostics.Contracts;

namespace Cryptopals
{
    static public class Converters
    {
        static public byte[] HexToBytes(string hex)
        {
            Contract.Requires(hex != null);
            Contract.Requires(hex.Length % 2 == 0);
            Contract.Ensures(Contract.Result<byte[]>() != null);

            return Enumerable.Range(0, hex.Length / 2)
                             .Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16))
                             .ToArray();
        }

        static public string BytesToHex(byte[] bin)
        {
            Contract.Requires(bin != null);

            return BitConverter.ToString(bin).Replace("-", String.Empty);
        }

        static public string BytesToString(byte[] bytes)
        {
            Contract.Requires(bytes != null);

            return Encoding.ASCII.GetString(bytes);
        }

        static public byte[] StringToBytes(string str)
        {
            Contract.Requires(str != null);
            Contract.Ensures(Contract.Result<byte[]>() != null);

            return Encoding.ASCII.GetBytes(str);
        }
    }
}
