/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Security.Cryptography;

namespace freescan
{
    public static class Security
    {
        private const string iv = "5th02wedczakV0De";
        private const string key = "Tinw2h8yasaw0da@thp0rkoSa1w4cR58";

        public static string EncryptAESString(string plainText)
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

        public static string DecryptAESString(string encryptedText)
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
