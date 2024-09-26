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
    public class FileBackup
    {
        DataAccess dataAccess;
        FileTypes fileTypes;

        public FileBackup() 
        {
            dataAccess = new DataAccess();
            fileTypes = new FileTypes();
        }

        public void InitFileTypeBackup()
        {
            List<string> types = fileTypes.GetFileTypes();

            FileType fileType = new FileType();
            fileType.Key = Guid.NewGuid().ToString();
            fileType.Extension = types[0];
            dataAccess.SaveFileTypeItem(fileType);

            FileType fileType2 = new FileType();
            fileType2.Key = Guid.NewGuid().ToString();
            fileType2.Extension = types[1];
            dataAccess.SaveFileTypeItem(fileType2);

            FileType fileType3 = new FileType();
            fileType3.Key = Guid.NewGuid().ToString();
            fileType3.Extension = types[2];
            dataAccess.SaveFileTypeItem(fileType3);
        }
    }
}
