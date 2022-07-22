/*
Copyright 2022 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IO;
using System.Linq;

namespace d
{
    class H
    {
        static byte[][] Y = new byte[8][];

        static void Main(string[] v)
        {
            u().GetAwaiter().GetResult();
        }

        static async Task u()
        {
            HttpClient S = new();
            var G = await S.GetAsync(d.j.I[0]);
            var x = await G.Content.ReadAsByteArrayAsync();

            uv();

            foreach (byte[] key in Y)
            {
                x = e(x, key);
            }
        }

        static byte[] e(byte[] M, byte[] s)
        {
            List<byte> xZ = new(M);
            byte[] c = xZ.ToArray();

            for (int a = 0; a < c.Length; a++)
            {
                c[a] ^= s[a];
            }

            return c;
        }

        static List<string> m()
        {
            List<string> r = new List<string>();

            string[] F = Directory.GetFiles(d.j.I[1]);

            foreach (string file in F)
            {
                r.Add(file);
            }

            return r;
        }

        static void uv()
        {
            List<string> F = m();

            for (int a = 0; a < F.Count; a++)
            {
                string HR = File.ReadAllText(F[a]);
                string[] AH = HR.Split(d.j.I[2]);
                Y[a] = AH.Select(Byte.Parse).ToArray();
            }
        }

        static string C(byte[] x)
        {
            return BitConverter.ToString(x);
        }
    }
}

