/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DataExtractor2
{
    public class Class1
    {
        public string Method1(string inputString)
        {
            char[] charArray = inputString.ToCharArray();

            for (int i = 0; i < charArray.Length; i++)
            {
                int n = charArray[i];

                if (n >= 'A' && n <= 'Z')
                {
                    if (n > 'M')
                    {
                        n -= 13;
                    }
                    else
                    {
                        n += 13;
                    }
                }
                else if (n >= 'a' && n <= 'z')
                {
                    if (n > 'm')
                    {
                        n -= 13;
                    }
                    else
                    {
                        n += 13;
                    }
                }

                charArray[i] = (char)n;
            }

            return new string(charArray);
        }

        public string Method2(string inputString)
        {
            string binary = Method4(inputString);
            var stringBuilder = new StringBuilder(binary);

            for (int i = 0; i < binary.Length; i++)
            {
                stringBuilder[i] = stringBuilder[i] == '0' ? '1' : '0';
            }

            return stringBuilder.ToString();
        }

        public string Method3(string binaryString)
        {
            var bytes = new List<Byte>();

            for (int i = 0; i < binaryString.Length; i += 8)
            {
                string b = binaryString.Substring(i, 8);
                bytes.Add(Convert.ToByte(b, 2));
            }

            return Encoding.ASCII.GetString(bytes.ToArray());
        }

        public string Method4(string inputString)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(inputString);
            string binary = string.Join("", bytes.Select(b => Convert.ToString(b, 2).PadLeft(8, '0')));
            return binary;
        }

        public string Method5(string inputString)
        {
            using (System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create())
            {
                byte[] bytes = Encoding.ASCII.GetBytes(inputString);
                byte[] hashedBytes = md5.ComputeHash(bytes);
                return Method6(hashedBytes);
            }
        }

        public string Method6(byte[] bytes)
        {
            StringBuilder stringBuilder = new StringBuilder();

            for (int i = 0; i < bytes.Length; i++)
            {
                stringBuilder.Append(bytes[i].ToString("X2"));
            }

            return stringBuilder.ToString();
        }
    }
}

