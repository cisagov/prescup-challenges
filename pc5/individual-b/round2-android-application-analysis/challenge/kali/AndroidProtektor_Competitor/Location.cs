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
using Java.Nio.Channels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xamarin.Essentials;

namespace AndroidProtektor
{
    public class Location
    {
        public Location() { }

        public GeoLocation GetLocation()
        {
            GeoLocation location = new GeoLocation();

            try
            {
                var geolocation = Geolocation.GetLastKnownLocationAsync().Result;

                if (geolocation != null)
                {
                    location.Latitude = geolocation.Latitude;
                    location.Longitude = geolocation.Longitude;
                    location.Altitude = geolocation.Altitude;
                }
            }
            catch (Exception ex)
            {
                // Handle not supported on device exception\
                return null;
            }

            return location;
        }
    }
}
