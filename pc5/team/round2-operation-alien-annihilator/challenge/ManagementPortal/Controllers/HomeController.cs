/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using ManagementPortal.Data.Models;
using ManagementPortal.Models;
using ManagementPortal.Services;
using MongoDB.Driver;
using MongoDB.Driver.Linq;
using Microsoft.AspNetCore.StaticFiles;

namespace ManagementPortal.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly IHostEnvironment _webHostEnvironment;
        private readonly UsersService _usersService;  
        private readonly InventoryService _inventoryService;
        private static HttpClient httpClient = new HttpClient();

        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory, IConfiguration configuration, IHostEnvironment webHostEnvironment, UsersService usersService, InventoryService inventoryService)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _webHostEnvironment = webHostEnvironment;
            _usersService = usersService;
            _inventoryService = inventoryService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Personnel()
        {
            if(!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            PersonnelViewModel model = new PersonnelViewModel();

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Personnel(PersonnelViewModel model)
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            if (model == null)
            {
                model = new PersonnelViewModel();
                model.Message = "Please provide a search value.";
                model.Users = new List<User>();
                return View(model);
            }

            if (string.IsNullOrWhiteSpace(model.Search))
            {
                model.Message = "Please provide a search value.";
                model.Users = new List<User>();
                return View(model);
            }

            try
            {
                //IMongoCollection<User> usersCollection = client.GetDatabase("webapp").GetCollection<User>("Users");
                //model.Users = usersCollection.Find(_ => true).ToList();
                
                List<User> users = _usersService.GetAsync().Result.Where(u => u.FirstName.ToLower() == model.Search.ToLower() || u.LastName.ToLower() == model.Search.ToLower()).ToList();
                model.Users = users;
            }
            catch (Exception ex)
            {
                model.Message = ex.Message + ex.StackTrace;
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> PersonnelId(PersonnelViewModel model)
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            if (model == null)
            {
                model = new PersonnelViewModel();
                model.Message = "Please provide a search value.";
                model.Users = new List<User>();
                return View("Personnel", model);
            }

            if (string.IsNullOrWhiteSpace(model.Search))
            {
                model.Message = "Please provide a search value.";
                model.Users = new List<User>();
                return View("Personnel", model);
            }

            if (model.Search == "1")
            {
                model.Users = new List<User>();
                return View("Personnel", model);
            }

            try
            {
                var connectionString ="mongodb://localhost:27017";
                var client = new MongoClient(connectionString);           
                IMongoDatabase db = client.GetDatabase("webapp");
                var collection = db.GetCollection<User>("Users");
                var results = collection.Find("{RoleId:"  + model.Search + "}");
                model.Users = results.ToList();          
            }
            catch (Exception ex)
            {
                model.Message = ex.Message + ex.StackTrace;
            }

            return View("Personnel", model);
        }

        public IActionResult Inventory()
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            InventoryViewModel model = new InventoryViewModel();
            model.InventoryItems = _inventoryService.GetAsync().Result.ToList();

            return View(model);
        }

        [HttpPost]
        public IActionResult Inventory(InventoryViewModel model)
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            if (model == null)
            {
                model = new InventoryViewModel();
                model.Message = "Please provide a search value.";
                model.InventoryItems = new List<Inventory>();
                return View(model);
            }

            if (string.IsNullOrWhiteSpace(model.SearchTerm))
            {
                model.Message = "Please provide a search value.";
                model.InventoryItems = new List<Inventory>();
                return View(model);
            }

            List<Inventory> inventoryItems = _inventoryService.GetAsync().Result.Where(i => i.Name.ToLower() == model.SearchTerm.ToLower() || i.Description.ToLower() == model.SearchTerm.ToLower()).ToList();
            model.InventoryItems = inventoryItems;

            return View(model);
        }

        public IActionResult Login()
        {
            LoginViewModel model = new LoginViewModel();
            return View(model);
        }

        [HttpPost]
        public IActionResult Login(LoginViewModel model)
        {
            if (!string.IsNullOrWhiteSpace(model.Username) && !string.IsNullOrWhiteSpace(model.Password))
            {
                User? user = _usersService.GetAsync().Result.Where(u => u.Username.ToLower() == model.Username.ToLower() && u.Password == model.Password).FirstOrDefault();

                if (user != null)
                {
                    HttpContext.Session.SetString("IsLoggedIn", "true");
                    HttpContext.Session.SetString("CurrentUser", user.Username + " " + user.LastName);
                    HttpContext.Session.SetString("CurrentUserRole", user.RoleId.ToString());
                    HttpContext.Session.SetString("CurrentUserId", user.Id.ToString());
                    HttpContext.Session.SetString("CurrentUserEmail", user.Email.ToString());
                    return View("Index");
                }
                else
                {
                    model.Message = "Invalid login credentials";
                }
            }
            else
            {
                model.Message = "Invalid login credentials";
            }

            return View(model);
        }

        public IActionResult Logout()
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            HttpContext.Session.SetString("IsLoggedIn", "false");
            HttpContext.Session.SetString("CurrentUser", string.Empty);
            HttpContext.Session.SetString("CurrentUserRole", string.Empty);
            return View("Index");
        }

        public FileContentResult DownloadFile(string filePath)
        {         
            byte[] bytes = Array.Empty<byte>();
            string contentType = "text/plain";

            try
            {                
                new FileExtensionContentTypeProvider().TryGetContentType(filePath, out contentType);                             
                string path = Path.Combine(_webHostEnvironment.ContentRootPath, "Files/") + filePath;            
                bytes = System.IO.File.ReadAllBytes(path);  
            }
            catch (Exception exc)
            {

            }                                                             
            
            return new FileContentResult(bytes, contentType);
        }

        public IActionResult Wiki()
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            WikiViewModel model = new WikiViewModel();
            List<string> files = new List<string>();
            string[] filePaths = Directory.GetFiles(Path.Combine(_webHostEnvironment.ContentRootPath, "Files/"), "*", SearchOption.AllDirectories);
            
            foreach (string filePath in filePaths)
            {
                 files.Add(filePath);
            }    

            model.Files = files;                                                             

            if (files.Count == 0)
            {
                model.Message = "There are no files available at this time.";
            }

            return View(model);
        }

        public IActionResult EditUser(string id)
        {
            EditUserViewModel model = new EditUserViewModel();

            if (!string.IsNullOrEmpty(id))
            {
                model.Id = id;

                User? user = _usersService.GetAsync().Result.Where(u => u.Id.ToLower() == id.ToLower()).FirstOrDefault();

                if (user != null)
                {
                    model.Username = user.Username;
                    model.FirstName = user.FirstName;
                    model.LastName = user.LastName;
                    model.Email = user.Email;

                    return View(model);
                }
                else
                {
                    model.Message = "Invalid user id.";
                }
            }
            else
            {
                model.Message = "Invalid user id.";
            }

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> EditUser(EditUserViewModel model)
        {
            User? user = _usersService.GetAsync().Result.Where(u => u.Id.ToLower() == model.Id.ToLower()).FirstOrDefault();

            if (user != null)
            {
                user.Username = model.Username;
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;

                if (!string.IsNullOrWhiteSpace(model.Password))
                {
                    user.Password = model.Password;
                }

                user.Email = model.Email;
                user.RoleId = 1;
                bool result = await _usersService.UpdateAsync(user.Id, user);
                model.Message = "User updated successfully";

                return View(model);
            }
            else
            {
                model.Message = "Invalid user id.";
            }

            return View(model);
        }

        public async Task<IActionResult> Logs()
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            LogsViewModel model = new LogsViewModel();                      
            model.LogEndpoint = "http://10.1.1.172/logs/logs.txt";
            model.LogData = await httpClient.GetStringAsync(model.LogEndpoint);

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Logs(LogsViewModel model)
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }
                   
            model.LogData = await httpClient.GetStringAsync(model.LogEndpoint);

            return View(model);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private bool ConfirmLoginStatus()
        {
            if (HttpContext.Session.GetString("IsLoggedIn") == null ||
                HttpContext.Session.GetString("IsLoggedIn") == "false")
            {
                return false;
            }

            return true;
        }
    }
}
