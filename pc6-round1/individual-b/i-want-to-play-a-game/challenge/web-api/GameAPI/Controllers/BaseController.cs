using GameAPI.Data;
using GameAPI.Data.Models;
using Microsoft.AspNetCore.Mvc;

namespace GameAPI.Controllers
{
    public class BaseController : Controller
    {
        private readonly IConfiguration _configuration;
        GameAPIContext _gameAPIContext;

        public BaseController(IConfiguration configuration, GameAPIContext gameAPIContext)
        {
            _configuration = configuration;
            _gameAPIContext = gameAPIContext;
        }

        [NonAction]
        [ApiExplorerSettings(IgnoreApi = true)]
        protected bool IsUserAuthenticated()
        {
            if (!Request.Headers.ContainsKey("UserAuthToken"))
            {
                return false;
            }

            string userAuthToken = Request.Headers["UserAuthToken"].FirstOrDefault();

            User user = _gameAPIContext.Users.Where(u => u.AuthToken == userAuthToken).FirstOrDefault();

            if (user == null)
            {
                return false;
            }
            return true;
        }
    }
}
