using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.Linq;

namespace Cryptopals
{
    static public class Analysis
    {
        public struct KeyLength
        {
            public readonly int Length;
            public readonly double Distance;

            public KeyLength(int length, double distance)
            {
                Length = length;
                Distance = distance;
            }
        }

        public struct ScoredBin
        {
            public readonly long Score;
            public readonly byte[] Data;

            public ScoredBin(long score, byte[] data)
            {
                Score = score;
                Data = data;
            }
        }

        static Dictionary<char, long> Weights = new Dictionary<char, long>()
        {
            { 'e', 13 },
            { 't', 12 },
            { 'a', 11 },
            { 'o', 10 },
            { 'i', 9 },
            { 'n', 8 },
            { ' ', 7 },
            { 's', 6 },
            { 'h', 5 },
            { 'r', 4 },
            { 'd', 3 },
            { 'l', 2 },
            { 'u', 1 }
        };

        static long Weight(char c)
        {
            var lower = Char.ToLower(c, CultureInfo.InvariantCulture);
            if (Weights.ContainsKey(lower))
            {
                return Weights[lower];
            }

            if (c < 32 || c > 127)
            {
                return -15;
            }

            return 0;
        }

        static public long Score
            (string str) => str.Aggregate(0L, (acc, c) => acc + Weight(c));

        static int BitsSet(byte b)
        {
            var result = 0;

            while (b > 0)
            {
                if ((b & 1) == 1)
                {
                    ++result;
                }

                b >>= 1;
            }

            return result;
        }

        static public long HammingDistance(byte[] a, byte[] b)
        {
            Contract.Requires(a != null);
            Contract.Requires(b != null);

            return a.Zip(b, (l, r) => (byte)(l ^ r))
                .Aggregate(0L, (acc, v) => acc + BitsSet(v));
        }

        public static double WeightedHammingDistance(byte[] a, byte[] b)
        {
            Contract.Requires(a != null);
            Contract.Requires(a.Length > 0);

            return (double)HammingDistance(a, b) / a.Length;
        }

        public static List<KeyLength> FindKeyLength(byte[] encrypted, int maxKeyLength)
        {
            Contract.Requires(maxKeyLength > 0);
            Contract.Requires(encrypted != null);
            Contract.Requires(encrypted.Length >= maxKeyLength * 3);
            Contract.Ensures(Contract.Result<List<KeyLength>>() != null);
            
            return Enumerable.Range(1, maxKeyLength)
                .Select(i => new
                {
                    First = new ArraySegment<byte>(encrypted, 0, i).ToArray(),
                    Second = new ArraySegment<byte>(encrypted, i, i).ToArray(),
                    Third = new ArraySegment<byte>(encrypted, i * 2, i).ToArray(),
                    Length = i
                })
                .Select(o => new
                {
                    Distance = (WeightedHammingDistance(o.First, o.Second) + WeightedHammingDistance(o.Second, o.Third)) / 2,
                    Length = o.Length
                })
                .Select(o => new KeyLength(o.Length, o.Distance))
                .OrderBy(kl => kl.Distance)
                .ToList();
        }
    }
}
