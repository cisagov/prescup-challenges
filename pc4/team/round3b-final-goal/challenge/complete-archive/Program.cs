/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.IO;

namespace FinalProgram
{
    internal class Program
    {
        private static DataExtractor1.Class1 dataExtractor1 = new DataExtractor1.Class1();
        private static DataExtractor2.Class1 dataExtractor2 = new DataExtractor2.Class1();
        private static DataExtractor3.Class1 dataExtractor3 = new DataExtractor3.Class1();

        static void Main(string[] args)
        {
            string finalCoordinates = ProcessFile1();
            finalCoordinates = finalCoordinates + ProcessFile2();
            finalCoordinates = finalCoordinates + ProcessFile3();
            finalCoordinates = finalCoordinates + "/";
            finalCoordinates = finalCoordinates + ProcessFile4();
            finalCoordinates = finalCoordinates + ProcessFile5();
            finalCoordinates = finalCoordinates + ProcessFile6();

            Console.WriteLine("Final Coordinates: " + finalCoordinates);
        }

        private static string ProcessFile1()
        {
            var text = string.Empty;

            using (var sr = new StreamReader("data\\DataFile1.txt"))
            {
                text = sr.ReadToEnd();
            }

            string result = dataExtractor1.Method1(text).ToString();
            return result[733].ToString();
        }

        private static string ProcessFile2()
        {
            var text = string.Empty;

            using (var sr = new StreamReader("data\\DataFile2.txt"))
            {
                text = sr.ReadToEnd();
            }

            string result = dataExtractor2.Method4(text).ToString();
            result = dataExtractor2.Method4(result).ToString();
            return result[116].ToString();
        }

        private static string ProcessFile3()
        {
            var text = string.Empty;

            using (var sr = new StreamReader("data\\DataFile3.txt"))
            {
                text = sr.ReadToEnd();
            }

            string result = dataExtractor2.Method1(text).ToString();
            return result[393].ToString();
        }

        private static string ProcessFile4()
        {
            var text = string.Empty;

            using (var sr = new StreamReader("data\\DataFile4.txt"))
            {
                text = sr.ReadToEnd();
            }

            string result = dataExtractor3.Method1(text).ToString();
            return result[840].ToString();
        }

        private static string ProcessFile5()
        {
            var text = string.Empty;

            using (var sr = new StreamReader("data\\DataFile5.txt"))
            {
                text = sr.ReadToEnd();
            }

            string result = dataExtractor1.Method3(text).ToString();
            return result[257].ToString();
        }

        private static string ProcessFile6()
        {
            var text = string.Empty;

            using (var sr = new StreamReader("data\\DataFile6.txt"))
            {
                text = sr.ReadToEnd();
            }

            string result = dataExtractor2.Method3(text).ToString();
            return result[905].ToString();
        }
    }
}

