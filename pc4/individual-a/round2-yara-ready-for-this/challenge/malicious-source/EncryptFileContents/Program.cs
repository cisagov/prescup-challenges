/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

// open a file
// read all contents
// encrypt it and base 64 encode it
// overwrite file contents
// close file
// rename file

using System.Security.Cryptography;

string iv = "Gh56tref89aQwv4u";
string key = String.Empty;
string file = string.Empty;

if (args.Length == 3)
{
    Console.WriteLine("args[0]: " + args[0]);
    Console.WriteLine("args[1]: " + args[1]);
    Console.WriteLine("args[2]: " + args[2]);

    file = args[1];
    key = args[2];

    if (args[0] == "-e")
    {
        string encryptedFileName = file + ".encrypted";
        string plainText = File.ReadAllText(file);        
        string encryptedText = EncryptFileContents(plainText, key, iv);

        if (File.Exists(encryptedFileName))
        {
            File.Delete(encryptedFileName);
        }

        File.WriteAllText(encryptedFileName, encryptedText);
        File.Delete(file);
    }
    else if (args[0] == "-d")
    {
        string decryptedFileName = file.Replace(".encrypted", "");
        string encryptedText = File.ReadAllText(file);
        string decryptedText = DecryptFileContents(encryptedText, key, iv);

        if (File.Exists(decryptedFileName))
        {
            File.Delete(decryptedFileName);
        }

        File.WriteAllText(decryptedFileName, decryptedText);
        File.Delete(file);
    }
    else
    {
        Console.WriteLine("Usage to encrypt files: -e INPUT_FILE_PATH 16_char_key");
        Console.WriteLine("Usage to decrypt files: -d INPUT_FILE_PATH 16_char_key");
        Console.ReadLine();
    }
}
else
{
    Console.WriteLine("Usage to encrypt files: -e INPUT_FILE_PATH 16_char_key");
    Console.WriteLine("Usage to decrypt files: -d INPUT_FILE_PATH 16_char_key");
    Console.ReadLine();
}

static string EncryptFileContents(string plainText, string key, string iv)
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

static string DecryptFileContents(string cipherText, string key, string iv)
{
    string plaintext = string.Empty;

    using (Aes aes = Aes.Create())
    {
        aes.Key = System.Text.Encoding.Default.GetBytes(key);
        aes.IV = System.Text.Encoding.Default.GetBytes(iv);
        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        using (MemoryStream memoryStream = new MemoryStream(System.Convert.FromBase64String(cipherText)))
        {
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(cryptoStream))
                {
                    plaintext = srDecrypt.ReadToEnd();
                }
            }
        }
    }

    return plaintext;
}
