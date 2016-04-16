using NUnit.Framework;
using Cryptopals;
using System.IO;
using System;
using System.Linq;
using System.Diagnostics.Contracts;

namespace cryptopals_tests
{
    class Set1
    {
        [Test]
        public void Challenge1()
        {
            var str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            var bytes = Converters.HexToBytes(str);

            var actual = Convert.ToBase64String(bytes);
            var expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void Challenge2()
        {
            var message = "1c0111001f010100061a024b53535009181c";
            var key = "686974207468652062756c6c277320657965";
            var expected = "746865206b696420646f6e277420706c6179";

            var actual = Encryption.RepeatedXor(Converters.HexToBytes(key), Converters.HexToBytes(message));

            Assert.AreEqual(actual, Converters.HexToBytes(expected));
        }

        [Test]
        public void Challenge3()
        {
            var message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            var expected = "Cooking MC's like a pound of bacon";

            var actual = Encryption.SingleByteXorBreak(Converters.HexToBytes(message));

            Contract.Assume(actual.Data != null);
            Assert.AreEqual(expected, Converters.BytesToString(actual.Data));
        }

        [Test]
        public void Challenge4()
        {
            Contract.Requires(TestContext.CurrentContext != null);
            Contract.Requires(TestContext.CurrentContext.TestDirectory != null);

            var expected = "Now that the party is jumping\n";

            var ch4Path = Path.Combine(TestContext.CurrentContext.TestDirectory, "Fixtures", "4.txt");

            Contract.Assume(!String.IsNullOrEmpty(ch4Path));
            var ch4 = File.ReadAllLines(ch4Path);

            Contract.Assert(ch4 != null);
            Contract.Assume(ch4.Any());
            var actual = Encryption.SingleByteXorFromList(ch4);

            Contract.Assume(actual.Data != null);
            Assert.AreEqual(expected, Converters.BytesToString(actual.Data));
        }

        [Test]
        public void Challenge5()
        {
            var message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            var key = "ICE";

            var expected = "0B3637272A2B2E63622C2E69692A23693A2A3C6324202D623D63343C2A26226324272765272A282B2F20430A652E2C652A3124333A653E2B2027630C692B20283165286326302E27282F";

            var actual = Converters.BytesToHex(Encryption.RepeatedXor(Converters.StringToBytes(key), Converters.StringToBytes(message)));

            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void Challenge6()
        {
            Contract.Requires(TestContext.CurrentContext != null);
            Contract.Requires(TestContext.CurrentContext.TestDirectory != null);

            var expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

            var ch6Path = Path.Combine(TestContext.CurrentContext.TestDirectory, "Fixtures", "6.txt");
            Contract.Assume(!String.IsNullOrEmpty(ch6Path));
            var ch6 = File.ReadAllText(ch6Path).Replace("\n", String.Empty);

            var bytestring = Convert.FromBase64String(ch6);
            var maxKeyLength = 41;
            Contract.Assume(bytestring.Length >= maxKeyLength * 3);
            var actual = Encryption.RepeatedXorBreak(bytestring, maxKeyLength, 10);

            Assert.AreEqual(expected, actual);
        }

        [Test]
        public void Challenge7()
        {
            Contract.Requires(TestContext.CurrentContext != null);
            Contract.Requires(TestContext.CurrentContext.TestDirectory != null);

            var expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

            var key = Converters.StringToBytes("YELLOW SUBMARINE");

            var ch7Path = Path.Combine(TestContext.CurrentContext.TestDirectory, "Fixtures", "7.txt");
            Contract.Assume(!String.IsNullOrEmpty(ch7Path));
            var ch6 = File.ReadAllText(ch7Path).Replace("\n", String.Empty);

            var bytestring = Convert.FromBase64String(ch6);

            var result = Encryption.AESECB(key, bytestring);
            var actual = Converters.BytesToString(result);

            Assert.AreEqual(expected, actual);
        }
    }
}
