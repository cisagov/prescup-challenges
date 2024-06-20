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
using SQLite;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AndroidProtektor
{
    public class DataAccess
    {
        SQLiteAsyncConnection Database;

        public DataAccess()
        {
        }

        public void Init()
        {
            if (Database != null)
                return;

            Database = new SQLiteAsyncConnection(Constants.DatabasePath, Constants.Flags);
            var result = Database.CreateTableAsync<FileType>().Result;
            var result2 = Database.CreateTableAsync<GeoLocationData>().Result;
        }

        public List<FileType> GetFileTypeItems()
        {
            Init();
            return Database.Table<FileType>().ToListAsync().Result;
        }

        public List<GeoLocationData> GetGeoLocationDataItems()
        {
            Init();
            return Database.Table<GeoLocationData>().ToListAsync().Result;
        }

        public FileType GetFileTypeItem(string id)
        {
            Init();
            return Database.Table<FileType>().Where(i => i.Id == id).FirstOrDefaultAsync().Result;
        }

        public GeoLocationData GetGeoLocationDataItem(string id)
        {
            Init();
            return Database.Table<GeoLocationData>().Where(i => i.Id == id).FirstOrDefaultAsync().Result;
        }

        public int SaveFileTypeItem(FileType item)
        {
            Init();

            if (!string.IsNullOrEmpty(item.Id))
            {
                return Database.UpdateAsync(item).Result;
            }
            else
            {
                item.Id = Guid.NewGuid().ToString();
                return Database.InsertAsync(item).Result;
            }
        }

        public int SaveGeoLocationDataItem(GeoLocationData item)
        {
            Init();

            if (!string.IsNullOrEmpty(item.Id))
            {
                return Database.UpdateAsync(item).Result;
            }
            else
            {
                item.Id = Guid.NewGuid().ToString();
                return Database.InsertAsync(item).Result;
            }
        }

        public int DeleteFileTypeItem(FileType item)
        {
            Init();
            return Database.DeleteAsync(item).Result;
        }

        public int DeleteGeoLocationDataItem(GeoLocationData item)
        {
            Init();
            return Database.DeleteAsync(item).Result;
        }
    }
}
