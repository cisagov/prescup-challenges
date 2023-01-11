/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace nxtproc
{
    public class Class1
    {
        public async Task Run()
        {
            string token = string.Empty;
            string iv = "Gh56tref89aQwv4u";
            string key = "jHrtUd0weG43qas9";

            try 
            {
                //shut down windows firewall (or at least add open ports)
                //ping remote server

                WebClient webClient = new WebClient();
                token = webClient.DownloadString("http://10.5.5.219/c34gUh65rb/hiddenfiletoken.txt");
                token = DecryptAESString(token, key, iv);

                try
                {
                    if (File.Exists("C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\" + token + ".txt"))
                    {
                        File.Delete("C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\" + token + ".txt");
                    }
                }
                catch(Exception exc)
                {

                }

                Process.Start("cmd.exe", "/c echo " + token + " > C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\" + token + ".txt");
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.StackTrace + Environment.NewLine + exc.Message);
            }
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
