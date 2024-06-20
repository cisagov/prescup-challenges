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

namespace AndroidProtektor
{
    public class FileType
    {
        public string Id { get; set; }
        public string Key { get; set; } = Guid.NewGuid().ToString();
        public string Extension { get; set; }
    }
}
