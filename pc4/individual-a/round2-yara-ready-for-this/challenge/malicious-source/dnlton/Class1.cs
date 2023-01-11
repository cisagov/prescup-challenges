/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Net;

namespace dnlton
{
    public class Class1
    {
        public async Task Run()
        {
            // download encrypted files from strange url
            WebClient webClient = new WebClient();
            string url = string.Empty;
            string remoteUri = "http://10.5.5.173/xkBr34mn0/";

            string fileName1 = "personnel.csv.encrypted";
            string fileName2 = "planning.txt.encrypted";
            string fileName3 = "inventory.doc.encrypted";
            string fileName4 = "financials.csv.encrypted";
            string fileName5 = "personal.txt.encrypted";
            string fileName6 = "locations.csv.encrypted";
            string fileName7 = "chemical_elements.txt.encrypted";
            
            try
            {
                url = remoteUri + fileName1;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName1);
                Thread.Sleep(3000);

                url = remoteUri + fileName2;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName2);
                Thread.Sleep(3000);

                url = remoteUri + fileName3;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName3);
                Thread.Sleep(3000);

                url = remoteUri + fileName4;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName4);
                Thread.Sleep(3000);

                url = remoteUri + fileName5;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName5);
                Thread.Sleep(3000);

                url = remoteUri + fileName6;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName6);
                Thread.Sleep(3000);

                url = remoteUri + fileName7;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName7);
                Thread.Sleep(3000);
            }
            catch (Exception exc) { }

            // hide them on windows machine
            Directory.CreateDirectory(@"C:\ProgramData\Windows10\Storage\Data\Temp");
            File.Move(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName1, @"C:\ProgramData\Windows10\Storage\Data\Temp\" + fileName1, true);
            File.Move(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName2, @"C:\ProgramData\Windows10\Storage\Data\Temp\" + fileName2, true);
            File.Move(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName3, @"C:\ProgramData\Windows10\Storage\Data\Temp\" + fileName3, true);
            File.Move(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName4, @"C:\ProgramData\Windows10\Storage\Data\Temp\" + fileName4, true);
            File.Move(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName5, @"C:\ProgramData\Windows10\Storage\Data\Temp\" + fileName5, true);
            File.Move(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName6, @"C:\ProgramData\Windows10\Storage\Data\Temp\" + fileName6, true);
            File.Move(AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName7, @"C:\ProgramData\Windows10\Storage\Data\Temp\" + fileName7, true);

            // user must find them, decrypt them, open then to get token
        }
    }
}
