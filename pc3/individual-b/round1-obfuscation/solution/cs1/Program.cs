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
using System.Threading.Tasks;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;

namespace d
{
    internal class H
    {
        private static byte[][] Y = new byte[8][];

        private static void Main(string[] v) => H.u().GetAwaiter().GetResult();

        private static async Task u()
        {
            byte[] M = await (await new HttpClient().GetAsync(j.I[0])).Content.ReadAsByteArrayAsync();
            H.uv();
            foreach (byte[] s in H.Y)
                M = H.e(M, s);
            var ascii = new ASCIIEncoding();
            Console.WriteLine(ascii.GetString(M, 0, M.Length));
        }

        private static byte[] e(byte[] M, byte[] s)
        {
            byte[] array = new List<byte>((IEnumerable<byte>)M).ToArray();
            for (int index = 0; index < array.Length; ++index)
                array[index] ^= s[index];
            return array;
        }

        private static List<string> m()
        {
            List<string> stringList = new List<string>();
            foreach (string file in Directory.GetFiles(j.I[1]))
                stringList.Add(file);
            return stringList;
        }

        private static void uv()
        {
            List<string> stringList = H.m();
            for (int index = 0; index < stringList.Count; ++index)
            {
                string[] strArray = File.ReadAllText(stringList[index]).Split(j.I[2]);
                H.Y[index] = ((IEnumerable<string>)strArray).Select<string, byte>(new Func<string, byte>(byte.Parse)).ToArray<byte>();
            }
        }

        private static string C(byte[] x) => BitConverter.ToString(x);
    }
    internal class j
    {
        public static j I = new j();
        private string[] mG;

        public string this[int f]
        {
            get
            {
                if (this.mG == null)
                {
                    using (MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String("AAEAAAD/////AQAAAAAAAAARAQAAAAMAAAAGAgAAABtodHRwOi8vbG9jYWxob3N0OjgwMDAvZmxhZzEGAwAAAAREYXRhBgQAAAACLCAL")))
                        this.mG = (string[])new BinaryFormatter().Deserialize((Stream)memoryStream);
                }
                return this.mG[f];
            }
        }
    }
}


