using System;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Security.Cryptography;

namespace Cryptopals
{
    static public class Encryption
    {
        static private byte[] ExpandKeyToLength(byte[] key, int length)
        {
            return Enumerable.Range(0, length)
                .Select(i => key[i % key.Length])
                .ToArray();
        }

        static public byte[] RepeatedXor(byte[] key, byte[] msg)
        {
            Contract.Requires(msg != null);
            Contract.Ensures(Contract.Result<byte[]>() != null);

            var expandedKey = ExpandKeyToLength(key, msg.Length);

            return msg.Select((b, i) => (byte)(b ^ expandedKey[i])).ToArray();
        }

        static public Analysis.ScoredBin SingleByteXorBreak(byte[] data)
        {
            var scoredCandidates = Enumerable.Range(0, 0xff)
                .Select(i => new byte[] { (byte)i })
                .Select(key => RepeatedXor(key, data))
                .Select(candidate => new Analysis.ScoredBin(Analysis.Score(Converters.BytesToString(candidate)), candidate))
                .OrderByDescending(c => c.Score);

            Contract.Assume(scoredCandidates.Any());
            return scoredCandidates.First();
        }

        static public Analysis.ScoredBin SingleByteXorFromList(string[] data)
        {
            Contract.Requires(data != null);
            Contract.Requires(data.Any());

            var scoredLines = data
                .Select(s => new { src = s, bin = Converters.HexToBytes(s) })
                .Select(o => SingleByteXorBreak(o.bin))
                .OrderByDescending(o => o.Score);

            Contract.Assume(scoredLines.Any());
            return scoredLines.First();
        }

        static Analysis.ScoredBin MultiByteXorBreak(byte[] encrypted, int keyLength)
        {
            var result = new byte[encrypted.Length];

            var score = 0L;

            Func<int, byte[]> interleavedElements = i => Enumerable.Range(0, encrypted.Length)
                    .Select(ix => keyLength * ix + i)
                    .Where(ix => ix < encrypted.Length)
                    .Select(ix => encrypted[ix])
                    .ToArray();

            for (var i = 0; i < keyLength; ++i)
            {
                var slice = interleavedElements(i);

                var decryptedWithScore = SingleByteXorBreak(slice);

                score += decryptedWithScore.Score;
                var decrypted = decryptedWithScore.Data;

                Contract.Assume(decrypted != null);

                for (var j = 0; j < decrypted.Length; ++j)
                {
                    Contract.Assume(j * keyLength + i < result.Length);
                    result[j * keyLength + i] = decrypted[j];
                }
            }

            return new Analysis.ScoredBin(score, result);
        }

        static public byte[] RepeatedXorBreak(byte[] encrypted, int maxKeyLength, int keysToCheck)
        {
            Contract.Requires(maxKeyLength > 0);
            Contract.Requires(keysToCheck > 0);
            Contract.Requires(encrypted != null);
            Contract.Requires(encrypted.Length >= maxKeyLength * 3);

            var keyDistanceQueue = Analysis.FindKeyLength(encrypted, maxKeyLength).Take(keysToCheck);

            var scoredCandidates = keyDistanceQueue
                .Select(kl => MultiByteXorBreak(encrypted, kl.Length))
                .OrderByDescending(c => c.Score)
                .Select(c => c.Data);

            Contract.Assume(scoredCandidates.Any());
            return scoredCandidates.First();
        }

        static public byte[] AESECB(byte[] key, byte[] message)
        {
            Contract.Requires(message != null);
            Contract.Requires(key != null);
            Contract.Ensures(Contract.Result<byte[]>() != null);

            var aes = new AesManaged
            {
                KeySize = 128,
                Key = key,
                BlockSize = 128,
                Mode = CipherMode.ECB,
                IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
            };

            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            return decryptor.TransformFinalBlock(message, 0, message.Length);
        }
    }
}
