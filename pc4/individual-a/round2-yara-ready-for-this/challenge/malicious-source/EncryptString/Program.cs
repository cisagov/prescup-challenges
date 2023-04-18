/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

// See https://aka.ms/new-console-template for more information

using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;

IConfiguration config = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .Build();

string inputFilePath = config.GetValue<string>("InputFilePath");
string outputFilePath = config.GetValue<string>("OutputFilePath");
string iv = config.GetValue<string>("IV");
//string key = config.GetValue<string>("Key");
string key = String.Empty;
string token = "";

if (args != null && args.Length == 1)
{
    key = args[0];

    using (var sr = new StreamReader(inputFilePath))
    {
        token = sr.ReadToEnd();
    }

    Console.WriteLine("args[0]: " + args[0]);
    Console.WriteLine("key: " + key);
    Console.WriteLine("iv: " + iv);
    Console.WriteLine("plain text input: " + token);
}

if (args != null && args.Length == 2)
{
    key = args[0];
    token = args[1];

    Console.WriteLine("args[0]: " + args[0]);
    Console.WriteLine("args[1]: " + args[1]);
    Console.WriteLine("key: " + key);
    Console.WriteLine("iv: " + iv);
    Console.WriteLine("plain text input: " + token);
}

using (Aes myAes = Aes.Create())
{
    string encrypted = EncryptAESString(token, key, iv);

    using (var sw = new StreamWriter(outputFilePath))
    {
        sw.Write(encrypted);
    }

    Console.WriteLine("encrypted text: " + encrypted);
}

static string EncryptAESString(string plainText, string key, string iv)
{
    using (Aes aes = Aes.Create())
    {
        aes.Key = System.Text.Encoding.Default.GetBytes(key);
        aes.IV = System.Text.Encoding.Default.GetBytes(iv);
        byte[] encrypted;

        ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

        using (MemoryStream memoryStream = new MemoryStream())
        {
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(plainText);
                }

                encrypted = memoryStream.ToArray();
            }
        }

        return System.Convert.ToBase64String(encrypted);
    }
}

