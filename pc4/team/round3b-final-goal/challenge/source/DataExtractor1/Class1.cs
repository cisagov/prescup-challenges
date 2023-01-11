/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Text;

namespace DataExtractor1
{
    public class Class1
    {
        public string Method1(string inputString)
        {
            var bytes = System.Text.Encoding.ASCII.GetBytes(inputString);
            return System.Convert.ToBase64String(bytes);
        }

        public string Method2(string inputString)
        {
            var bytes = System.Convert.FromBase64String(inputString);
            return System.Text.Encoding.ASCII.GetString(bytes);
        }

        public string Method3(string inputString)
        {
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(inputString);
            StringBuilder stringBuilder = new StringBuilder();

            for (int i = 0; i < bytes.Length; i++)
            {
                stringBuilder.Append(bytes[i].ToString("X2"));
            }

            return stringBuilder.ToString();
        }
    }
}

