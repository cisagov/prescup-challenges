/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Net;
using System.Security.Cryptography;

namespace xp32drv
{
    public class Class1
    {
        public async void Run()
        {
            //download a token and keep it in memory
            string token = string.Empty;
            string iv = "Gh56tref89aQwv4u";
            string key = "jHrtUd0weG43qas9";

            WebClient webClient = new WebClient();
            token = webClient.DownloadString("http://10.5.5.159/j3edcrop99/memorytoken.txt");
            token = DecryptAESString(token, key, iv);

            token = "Memory token: " + token;
        }

        private string DecryptAESString(string encryptedText, string key, string iv)
        {
            string decryptedText = null;

            using (Aes aes = Aes.Create())
            {
                aes.Key = System.Text.Encoding.Default.GetBytes(key);
                aes.IV = System.Text.Encoding.Default.GetBytes(iv);

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(System.Convert.FromBase64String(encryptedText)))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            decryptedText = streamReader.ReadToEnd();
                        }
                    }
                }
            }

            return decryptedText;
        }
    }
}
