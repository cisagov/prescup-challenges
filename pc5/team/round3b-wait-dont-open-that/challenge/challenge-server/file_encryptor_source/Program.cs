/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Security.Cryptography;

namespace file_encryptor;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Encrypting Files . . . ");

        string iv = "gr5@uC10pkzeD7yT";
        
        try
        {
            string filePath = args[0];          
            string key = args[1];  
            
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
        }
        catch (Exception exc){}

        Console.WriteLine("Done Encrypting Files . . . ");
    }
}

