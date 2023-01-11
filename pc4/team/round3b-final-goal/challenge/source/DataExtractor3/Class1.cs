/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Linq;
using System.Web;

namespace DataExtractor3
{
    public class Class1
    {
        public string Method1(string inputString)
        {
            char[] chars = inputString.ToCharArray();
            Array.Reverse(chars);
            return new string(chars);
        }

        public string Method2(string inputString)
        {
            return inputString.OrderBy(c => c).ToString();
        }

        public string Method3(string inputString)
        {
            return inputString.OrderByDescending(c => c).ToString();
        }

        public string Method4(int startIndex, int length, string inputString)
        {
            return inputString.Substring(startIndex, length);
        }

        public string Method5(string inputString)
        {
            return HttpUtility.UrlEncode(inputString);
        }

        public string Method6(string inputString)
        {
            return HttpUtility.UrlDecode(inputString);
        }

        public string Method7(string inputString)
        {
            return HttpUtility.HtmlEncode(inputString);
        }

        public string Method8(string inputString)
        {
            return HttpUtility.HtmlDecode(inputString);
        }
    }
}

