/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration;

namespace MerchCodesUI.Controllers
{
    public class BaseController : Controller
    {
        private readonly IConfiguration _configuration;

        protected static HttpClient httpClient = new();

        public BaseController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void AddAuthenticationHeaders()
        {
            if (User != null && User.Claims != null)
            {
                List<System.Security.Claims.Claim> claims = User.Claims.ToList();
                string id = claims?.FirstOrDefault(x => x.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", StringComparison.OrdinalIgnoreCase))?.Value;
                string email = claims?.FirstOrDefault(x => x.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", StringComparison.OrdinalIgnoreCase))?.Value;

                if (!httpClient.DefaultRequestHeaders.Contains("ApiKey"))
                {
                    httpClient.DefaultRequestHeaders.Add("ApiKey", _configuration.GetValue<string>("ApiKey"));
                }

                if (!httpClient.DefaultRequestHeaders.Contains("UserId"))
                {
                    httpClient.DefaultRequestHeaders.Add("UserId", id);
                }

                if (!httpClient.DefaultRequestHeaders.Contains("UserEmail"))
                {
                    httpClient.DefaultRequestHeaders.Add("UserEmail", email);
                }
            }
        }
    }
}

