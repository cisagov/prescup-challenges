/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesInventoryApi.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MerchCodesInventoryApi.Controllers
{
    public class BaseController : Controller
    {
        private readonly IConfiguration _configuration;
        ApplicationDbContext _applicationDbContext;

        public BaseController(IConfiguration configuration, ApplicationDbContext applicationDbContext)
        {
            _configuration = configuration;
            _applicationDbContext = applicationDbContext;
        }

        [NonAction]
        [ApiExplorerSettings(IgnoreApi = true)]
        protected bool IsUserAuthenticated()
        {
            if (!Request.Headers.ContainsKey("ApiKey") ||
                !Request.Headers.ContainsKey("UserId") ||
                !Request.Headers.ContainsKey("UserEmail"))
            {
                return false;
            }

            string apiKey = Request.Headers["ApiKey"].FirstOrDefault();
            string userId = Request.Headers["UserId"].FirstOrDefault();
            string userEmail = Request.Headers["UserEmail"].FirstOrDefault();

            if (apiKey != _configuration.GetValue<string>("ApiKey"))
            {
                return false;
            }

            IdentityUser user = _applicationDbContext.Users.Where(u => u.Id == userId).FirstOrDefault();

            if (user == null)
            {
                return false;
            }

            if (userEmail != user.Email)
            {
                return false;
            }

            return true;
        }
    }
}

