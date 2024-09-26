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
using System.IO;
using System.Linq;
using System.Text;
using Xamarin.Essentials;

namespace AndroidProtektor
{
    public class FileFinder
    {
        DataAccess dataAccess;

        public FileFinder() 
        {
            dataAccess = new DataAccess();
        }

        public List<string> FindFiles() 
        {
            List<string> files = new List<string>();
            List<FileType> items = dataAccess.GetFileTypeItems();

            foreach (FileType fileType in items)
            {
                files.AddRange(Directory.GetFiles(FileSystem.AppDataDirectory, "*." + fileType.Extension, SearchOption.AllDirectories).ToList());
            }

            return files;
        }
    }
}
