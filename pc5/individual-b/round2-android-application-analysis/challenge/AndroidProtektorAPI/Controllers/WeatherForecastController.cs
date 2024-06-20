/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;

namespace AndroidProtektorAPI.Controllers
{
    [ApiController]
    [Route("api/protektor")]
    public class WeatherForecastController : ControllerBase
    {
        HttpClient client = new HttpClient();

        private static readonly string[] Summaries = new[]
        {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

        private readonly ILogger<WeatherForecastController> _logger;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("GetWeatherForecast")]
        public IEnumerable<WeatherForecast> GetWeatherForecast()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [HttpGet]
        [Route("GetLocationOptions")]
        public string GetLocationOptions()
        {
            return "false";
        }

        [HttpGet]
        [Route("GetImageOptions")]
        public string GetImageOptions()
        {
            return "false";
        }

        [HttpGet]
        [Route("GetClientKey")]
        public string GetClientKey()
        {
            string clientKey = string.Empty;
            string clientId = string.Empty;

            var Stream1 = new FileStream("ClientId.txt", FileMode.Open, FileAccess.Read);

            using (var streamReader = new StreamReader(Stream1, Encoding.UTF8))
            {
                clientId = streamReader.ReadToEnd();
            }

            if (Request.Headers.TryGetValue("ClientId", out var headerValue))
            {
                if (headerValue.ToString() != clientId)
                {
                    return "Invalid or missing header ClientId";
                }
            }
            else
            {
                return "Missing or invalid header ClientId";
            }

            var Stream2 = new FileStream("ClientKey.txt", FileMode.Open, FileAccess.Read);

            using (var streamReader = new StreamReader(Stream2, Encoding.UTF8))
            {
                clientKey = streamReader.ReadToEnd();
            }

            return clientKey;
        }

        [HttpPost]
        [Route("UploadFile")]
        public bool UploadFile(IFormFile file)
        {
            // try
            // {
            //     string path = Path.GetFullPath(Path.Combine(Environment.CurrentDirectory, _configuration.GetValue<string>("FilePath")));

            //     if (!Directory.Exists(path))
            //     {
            //         Directory.CreateDirectory(path);
            //     }

            //     using (var fileStream = new FileStream(Path.Combine(path, file.FileName), FileMode.Create))
            //     {
            //         file.CopyTo(fileStream);
            //     }

            //     return true;
            // }
            // catch (Exception exc)
            // {
            //     return false;
            // }

            return true;
        }
    }
}
