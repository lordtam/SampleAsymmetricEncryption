using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace server.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SampleController : ControllerBase
    {
        public class Payload
        {
            public string Name { get; set; }
        }

        [HttpPost]
        public IActionResult Decrypt([FromBody] Payload payload)
        {
            byte[] rgb = Convert.FromBase64String(payload.Name);
            string decryptedValue = Encoding.UTF8.GetString(CreateRsaProviderFromPrivateKey().Decrypt(rgb, false));

            return Ok($"Original data is {decryptedValue}");
        }

        private RSACryptoServiceProvider CreateRsaProviderFromPrivateKey()
        {
            string privateKey = @"-----BEGIN RSA PRIVATE KEY-----
                                MIIEogIBAAKCAQEAgT00sMZGCFtROnlT7R95/RPT/JmFwRpM0YkXmzfx26ryL4dB
                                WGFVnku1cjf9zjO5Xc6Oxte80Pdqv6LL9bGbWFUyLyCp9M4PLAAuTA2OGxB96BqL
                                mrLjtaEbvqc6ra+uqH4Pnk17RSarpjUVtOXgyGhN44fLe7OoXVbbICNGDMx+1t/2
                                T/NjMUf8pQEMcHxGZjK67NuosyiETXyR4FUXWvJh+KaZ6STnMb2TEKnUb1Zy4ul1
                                Nj575YJCsF4XPozzi/b5VBr7XP7dSX23oKvRqUJ6yaMUlauI6hw7ZtNB0EDagHxl
                                bO6RNJcejeErgbdcOgXTaIb27Lj3ez7/n7yLnwIDAQABAoIBABjieyHKm7OCOcrD
                                j9hppiiHx9qsiOecs8vo1MXLaON+L/Hc3kUxQLYhJ8fdZh5tMTURz8YTxkSKT2Ck
                                7Rba4umIRghzBqafgqZbRo7YUVN+wm+NpPHdniDb66azNoY4/K1u0H0PuDuhbY2s
                                TQiu9rA//Tdhb1nbRwDp93lhsVxHQdwOtrRy7Ds4M0pOzzaqxM2fedcnXl+WdJkt
                                q58xl2gCitZs/VOuSxBx/ZJkdfMrddjuDXgWjL0n+mVoyvLo9TW08MVTizQ+NnHe
                                +ytL9YxwbGaRvHakfK+vlESPcQG3rttERnKBKHHQnU1bburxLBrliC0RBkoQtTYE
                                KsjWISECgYEAt6pxe2Q/hDVxQbo+yRQsK0270IQwiNTHAwmJ4Um4SFu78T+LCf6N
                                kmQX4NhxWvjXY9nS5iWmDXXl8M9vlBPlr3HFubdh1hPq50/8RJ5heNEAg4IUjIi6
                                PlIdnRgJjTYYGPzku9L6ylMw4z4BY5nBMvReZYHEQZJZjR461L5t7m8CgYEAtCNa
                                CSs/p293FmaG6dhjRHPZ5/tg/E6ChzeG6OMcKEmbC8a5QcxfFLju6UAHx27MnXYx
                                Y+lrzcUa8HQHJ1WASuKK3b4wr3ax1u8cMllb6yp17IHg9NIxWcPJ35u97XaKsHQr
                                9x85hi+qNeqRH4R5EkkhZHnlrP41o6OGmIfSzdECgYBU+rzlHb4xutR7V+RC/11s
                                b9wNn4whU2n9YsV0ArsMZ71u4zq+1hPE/yD5PMw+DlMCdT+akyLgqYNJx4DV39rv
                                MVIOGuZeufp/KkgLq8hnsTRupJpDZ+Pcf/wJupx4xOWjcieXLAgz4wgErKTR48s7
                                e0vN5Zvbxw4+OBV6Z93PawKBgDkQjeAjtDl9ZRNSjWCc7O1tadVEW/fxgwYEwBcc
                                gvn8P0KexGckr+Yno39+ijhSUD19iK3m7wCzdRJBH1cFjeurEmSmcFPVXQcCnkMQ
                                7b50qACxMCs+PuX50QSmGKeWCt9VHexeFuH8TYZg9XIvjA8P3aUvvGNt8F4TWnsN
                                Y+lRAoGACd5tzigUIu+Ig+OC9m4Fa9B3j8J59zHQ2V1uITkg1r3G6USBLO4DTjNO
                                EVOyloulF4VOhR31w94/dkuZDNCN0UQhXA9XmPNAG0BLjcnHoSd5ci6XyThDHL5v
                                XeqK1PeoMve+KvQMoI0t44U9ZhOZXrFqTtGp1jYJirblJ1hQeyY=
                                -----END RSA PRIVATE KEY-----";

            string KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
            string KEY_FOOTER = "-----END RSA PRIVATE KEY-----";
            string keyFormatted = privateKey;
            int cutIndex = keyFormatted.IndexOf(KEY_HEADER);
            keyFormatted = keyFormatted.Substring(cutIndex, keyFormatted.Length - cutIndex);
            cutIndex = keyFormatted.IndexOf(KEY_FOOTER);
            keyFormatted = keyFormatted.Substring(0, cutIndex + KEY_FOOTER.Length);
            keyFormatted = keyFormatted.Replace(KEY_HEADER, "");
            keyFormatted = keyFormatted.Replace(KEY_FOOTER, "");
            keyFormatted = keyFormatted.Replace("\r", "");
            keyFormatted = keyFormatted.Replace("\n", "");
            keyFormatted = keyFormatted.Trim();

            byte[] privateKeyBits = Convert.FromBase64String(keyFormatted);

            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAParameters RSAparams = new RSAParameters();

            using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twobytes = 0;
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130)
                {
                    binr.ReadByte();
                }
                else if (twobytes == 0x8230)
                {
                    binr.ReadInt16();
                }
                else
                {
                    throw new Exception("Unexpected value read binr.ReadUInt16()");
                }

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102)
                {
                    throw new Exception("Unexpected version");
                }

                bt = binr.ReadByte();
                if (bt != 0x00)
                {
                    throw new Exception("Unexpected value read binr.ReadByte()");
                }

                RSAparams.Modulus = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Exponent = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.D = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.P = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Q = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DP = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DQ = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
            }

            RSA.ImportParameters(RSAparams);
            return RSA;
        }

        private int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowByte = 0x00;
            byte highByte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)
            {
                return 0;
            }

            bt = binr.ReadByte();

            if (bt == 0x81)
            {
                count = binr.ReadByte();
            }
            else if (bt == 0x82)
            {
                highByte = binr.ReadByte();
                lowByte = binr.ReadByte();
                byte[] modInt = { lowByte, highByte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modInt, 0);
            }
            else
            {
                count = bt;
            }

            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }

            binr.BaseStream.Seek(-1, SeekOrigin.Current);
            return count;
        }
    }
}