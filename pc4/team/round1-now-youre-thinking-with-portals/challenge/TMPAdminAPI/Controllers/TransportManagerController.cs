// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using Microsoft.AspNetCore.Mvc;
using TMPAdminAPI.Data;
using TMPAdminAPI.Data.Models;
using TMPAdminAPI.Models;

namespace TMPAdminAPI.Controllers
{
    [ApiController]
    public class TransportManagerController : Controller
    {
        private readonly TmpApiContext _context;

        public TransportManagerController(TmpApiContext context)
        {
            _context = context;
        }

        [HttpPost]
        [Route("api/[controller]/generatetoken")]
        public string GenerateToken([FromBody] GenerateTokenModel model)
        {
            if (!VerifyApiKey(model.ApiKey))
            {
                return "Invalid API key.";
            }

            AppKey appKey = _context.AppKeys.Where(k => k.KeyType == "API").FirstOrDefault();

            if (appKey != null)
            {
                appKey.IsAvailable = true;
                _context.Update(appKey);
                _context.SaveChanges();
            }

            return "The token has been generated and saved on the server.";
        }

        [HttpPost]
        [Route("api/[controller]/resetdatabase")]
        public bool ResetDatabase()
        {
            throw new NotImplementedException();
            return false;
        }

        [HttpGet]
        [Route("api/[controller]/requestchallengetoken")]
        public string RequestChallengeToken()
        {
            AppKey appKey = _context.AppKeys.Where(k => k.KeyType == "API" && k.IsAvailable).FirstOrDefault();

            if (appKey == null)
            {
                return "The challenge token has not been generated.";
            }
            
            try
            {
                TransportSystem transportSystem = _context.TransportSystems.Where(t => t.Name == "Damage Control").FirstOrDefault();

                if (transportSystem != null)
                {
                    transportSystem.Status = "Online";
                    _context.Update(transportSystem);
                    _context.SaveChanges();
                }

                // Open the text file using a stream reader.
                using (var sr = new StreamReader("token5.txt"))
                {
                    // Read the stream as a string, and write the string to the console.
                    return "TOKEN #5: " + sr.ReadToEnd();
                }
            }
            catch (IOException e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }

            return "An error occurred. Please try again";
        }

        [HttpPost]
        [Route("api/[controller]/getapikey")]
        public string GetApiKey(LoginModel model)
        {
            User user = _context.Users.Where(u => u.Username.ToLower() == model.Username.ToLower() && u.Password == model.Password).FirstOrDefault();

            if (user != null)
            {
                if (user.RoleId == (int)Enums.Roles.Admin)
                {
                    return "API Key: " + _context.AppKeys.Where(k => k.KeyType == "API").Single().KeyValue;
                }
                else
                {
                    return "Please login with an account that has an admin role.";
                }
            }

            return "Invalid username or password";
        }

        private bool VerifyApiKey(string key)
        {
            return key == _context.AppKeys.Where(k => k.KeyType == "API").Single().KeyValue;
        }
    }
}
