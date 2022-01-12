/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace x
{
    internal class g
    {
        private static void Main(string[] xo) => g.C().GetAwaiter().GetResult();

        private static async Task C()
        {
            byte[][] f = new byte[4][]
            {
                new byte[16] { 151, 82, 254, 123, 105, 128, 154, 235, 40, 104, 177, 93, 153, 205, 206, 36 },
                new byte[16] { 183, 90, 159, 24, 247, 9, 132, 32, 198, 125, 111, 7, 162, 223, 198, 134 },
                new byte[16] { 76, 189, 179, 117, 170, 178, 197, 134, 148, 55, 45, 122, 45, 98, 147, 125 },
                new byte[16] { 214, 40, 66, 129, 252, 175, 225, 239, 197, 185, 117, 50, 162, 148, 171, 11 }
            };
            byte[] numArray1 = await (await new HttpClient().GetAsync(MV.Y[0])).Content.ReadAsByteArrayAsync();
            byte[] array1 = ((IEnumerable<byte>)numArray1).Take<byte>(16).ToArray<byte>();
            byte[] numArray2 = g.r(g.k(g.h(((IEnumerable<byte>)numArray1).Skip<byte>(16).ToArray<byte>(), array1)));
            foreach (byte[] M in ((IEnumerable<byte[]>)f).Reverse<byte[]>())
            {
                byte[] array2 = ((IEnumerable<byte>)numArray2).Take<byte>(16).ToArray<byte>();
                numArray2 = g.l9(((IEnumerable<byte>)numArray2).Skip<byte>(16).ToArray<byte>(), array2, M);
            }
            f = (byte[][])null;
            var ascii = new ASCIIEncoding();
            Console.WriteLine(ascii.GetString(numArray2, 0, numArray2.Length));
        }

        private static byte[] h(byte[] l, byte[] f8) => g.l9(l, f8, new byte[16] { 87, 40, 49, 153, 183, 115, 86, 62, 96, 251, 174, 183, 17, 247, 81, 177 });
        private static byte[] t(byte[] l)
        {
            byte[] M = new byte[16] { 76, 191, 10, 248, 14, 117, 44, 8, 20, 221, 107, 224, 59, 36, 125, 154 };
            return g.l9(((IEnumerable<byte>)l).Skip<byte>(16).ToArray<byte>(), ((IEnumerable<byte>)l).Take<byte>(16).ToArray<byte>(), M);
        }

        private static byte[] k(byte[] l)
        {
            byte[] M = new byte[16] { 166, 223, 26, 65, 249, 49, 214, 197, 12, 73, 77, 34, 27, 89, 107, 115 };
            byte[] numArray = g.t(l);
            byte[] array = ((IEnumerable<byte>)numArray).Take<byte>(16).ToArray<byte>();
            return g.l9(((IEnumerable<byte>)numArray).Skip<byte>(16).ToArray<byte>(), array, M);
        }

        private static byte[] r(byte[] l)
        {
            byte[] l1 = new byte[16] { 52, 144, 221, 76, 138, 177, 86, 232, 159, 181, 115, 16, 57, 223, 134, 136 };
            byte[] M = new byte[16] { 191, 5, 104, 52, 84, 113, 124, 249, 64, 233, 73, 238, 107, 182, 57, 245 };
            byte[] array = ((IEnumerable<byte>)l).Take<byte>(16).ToArray<byte>();
            return g.l9(((IEnumerable<byte>)l).Skip<byte>(16).ToArray<byte>(), array, g.j(l1, M));
        }

        private static byte[] j(byte[] l, byte[] M)
        {
            byte[] numArray = (byte[])l.Clone();
            for (int index = 0; index < M.Length; ++index)
                numArray[index] ^= M[index];
            return numArray;
        }

        private static byte[] l9(byte[] l, byte[] f8, byte[] M)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = M;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.IV = f8;
                using (MemoryStream memoryStream1 = new MemoryStream(l))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream1, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (MemoryStream memoryStream2 = new MemoryStream())
                        {
                            cryptoStream.CopyTo((Stream)memoryStream2);
                            return memoryStream2.ToArray();
                        }
                    }
                }
            }
        }
    }
    internal class MV
    {
        public static MV Y = new MV();
        private string[] G7;

        public string this[int H]
        {
            get
            {
                if (this.G7 == null)
                {
                    using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAARAQAAAAEAAAAGAgAAABtodHRwOi8vbG9jYWxob3N0OjgwMDAvZmxhZzIL")))
                        this.G7 = (string[])new BinaryFormatter().Deserialize((Stream)memoryStream);
                }
                return this.G7[H];
            }
        }
    }
}


