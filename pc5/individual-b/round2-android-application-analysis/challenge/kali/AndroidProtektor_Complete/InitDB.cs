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
    public  class InitDB
    {
        public InitDB()
        {
            try
            {
                DataAccess dataAccess = new DataAccess();

                // set 1
                if (dataAccess.GetGeoLocationDataItems().Count == 0)
                {
                    GeoLocationData geoData = new GeoLocationData();
                    geoData.Latitude = 41.505493;
                    geoData.Longitude = -81.68129;
                    geoData.CreationDate = "7/2/2023 6:08:43 PM";
                    dataAccess.SaveGeoLocationDataItem(geoData);

                    geoData = new GeoLocationData();
                    geoData.Latitude = 40.440624;
                    geoData.Longitude = -79.995888;
                    geoData.CreationDate = "7/13/2023 5:19:23 PM";
                    dataAccess.SaveGeoLocationDataItem(geoData);

                    geoData = new GeoLocationData();
                    geoData.Latitude = 39.103119;
                    geoData.Longitude = -84.512016;
                    geoData.CreationDate = "7/22/2023 1:51:19 PM";
                    dataAccess.SaveGeoLocationDataItem(geoData);

                    geoData = new GeoLocationData();
                    geoData.Latitude = 39.299236;
                    geoData.Longitude = -76.609383;
                    geoData.CreationDate = "7 /25/2023 11:59:40 PM";
                    dataAccess.SaveGeoLocationDataItem(geoData);

                    geoData = new GeoLocationData();
                    geoData.Latitude = 39.099724;
                    geoData.Longitude = -94.578331;
                    geoData.CreationDate = "8/12/2023 4:44:10 PM";
                    dataAccess.SaveGeoLocationDataItem(geoData);
                }

                //// set 2      
                //if (dataAccess.GetGeoLocationDataItems().Count == 0)
                //{
                //    GeoLocationData geoData = new GeoLocationData();
                //    geoData.Latitude = 41.505493;
                //    geoData.Longitude = -81.68129;
                //    geoData.CreationDate = "7/2/2023 6:08:43 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 40.440624;
                //    geoData.Longitude = -79.995888;
                //    geoData.CreationDate = "7/13/2023 5:19:23 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.099724;
                //    geoData.Longitude = -94.578331;
                //    geoData.CreationDate = "7/22/2023 1:51:19 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.299236;
                //    geoData.Longitude = -76.609383;
                //    geoData.CreationDate = "7/25/2023 11:59:40 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.103119;
                //    geoData.Longitude = -84.512016;
                //    geoData.CreationDate = "8/12/2023 4:44:10 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);
                //}

                //// set 3      
                //if (dataAccess.GetGeoLocationDataItems().Count == 0)
                //{
                //    GeoLocationData geoData = new GeoLocationData();
                //    geoData.Latitude = 39.099724;
                //    geoData.Longitude = -94.578331;
                //    geoData.CreationDate = "7/2/2023 6:08:43 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 40.440624;
                //    geoData.Longitude = -79.995888;
                //    geoData.CreationDate = "7/13/2023 5:19:23 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.103119;
                //    geoData.Longitude = -84.512016;
                //    geoData.CreationDate = "7/22/2023 1:51:19 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.299236;
                //    geoData.Longitude = -76.609383;
                //    geoData.CreationDate = "7/25/2023 11:59:40 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 41.505493;
                //    geoData.Longitude = -81.68129;
                //    geoData.CreationDate = "8/12/2023 4:44:10 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);
                //}

                //// set 4     
                //if (dataAccess.GetGeoLocationDataItems().Count == 0)
                //{
                //    GeoLocationData geoData = new GeoLocationData();
                //    geoData.Latitude = 41.505493;
                //    geoData.Longitude = -81.68129;
                //    geoData.CreationDate = "7/2/2023 6:08:43 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.099724;
                //    geoData.Longitude = -94.578331;
                //    geoData.CreationDate = "7/13/2023 5:19:23 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.103119;
                //    geoData.Longitude = -84.512016;
                //    geoData.CreationDate = "7/22/2023 1:51:19 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 39.299236;
                //    geoData.Longitude = -76.609383;
                //    geoData.CreationDate = "7/25/2023 11:59:40 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);

                //    geoData = new GeoLocationData();
                //    geoData.Latitude = 40.440624;
                //    geoData.Longitude = -79.995888;
                //    geoData.CreationDate = "8/12/2023 4:44:10 PM";
                //    dataAccess.SaveGeoLocationDataItem(geoData);
                //}
            }
            catch (System.Exception ex)
            {

            }
        }
    }
}
