/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using Android.App;
using Android.Content;
using Android.OS;
using Android.Runtime;
using Android.Views;
using Android.Widget;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static Android.Graphics.Path;

namespace AndroidProtektor
{
    public class FileTypes
    {
        public FileTypes() { }

        public List<string> GetFileTypes() 
        {
            List<string> results = new List<string>();

            results.Add("png");
            results.Add("jpg");
            results.Add("gif");

            //results.Add("xml");
            //results.Add("json");
            //results.Add("txt");

            //results.Add("pdf");
            //results.Add("doc");
            //results.Add("xls");

            //results.Add("pptx");
            //results.Add("docx");
            //results.Add("xlsx");

            return results;
        }
    }
}
