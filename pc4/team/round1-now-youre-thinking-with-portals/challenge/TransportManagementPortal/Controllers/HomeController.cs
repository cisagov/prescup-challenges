// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using System.Diagnostics;
using TransportManagementPortal.Data;
using TransportManagementPortal.Data.Models;
using TransportManagementPortal.Models;

namespace TransportManagementPortal.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        private readonly TmpContext _context;

        public HomeController(ILogger<HomeController> logger, IHttpClientFactory httpClientFactory, IConfiguration configuration, TmpContext context)
        {
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _context = context;
        }

        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Status()
        {
            TransportSystemStatusViewModel model = new TransportSystemStatusViewModel();
            List<TransportSystem> systems = _context.TransportSystems.ToList();
            model.TransportSystems = systems;

            return View(model);
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

            List<User> users = new List<User>();
            string constr = _configuration.GetConnectionString("DefaultConnection");

            using (NpgsqlConnection con = new NpgsqlConnection(constr))
            {
                string query = "select * from \"User\" where \"FirstName\" = '" + model.Search + "' or \"LastName\" = '" + model.Search + "'";
                using (NpgsqlCommand cmd = new NpgsqlCommand(query))
                {
                    cmd.Connection = con;
                    con.Open(); 

                    using (NpgsqlDataReader dr = cmd.ExecuteReader())
                    {
                        while (dr.Read())
                        {
                            users.Add(new User
                            {
                                Id = dr["Id"].ToString(),
                                Username = dr["Username"].ToString(),
                                Password = dr["Password"].ToString(),
                                FirstName = dr["FirstName"].ToString(),
                                LastName = dr["LastName"].ToString(),
                                Email = dr["Email"].ToString(),
                                RoleId = Convert.ToInt32(dr["RoleId"])
                            });
                        }
                    }
                }

                con.Close();
            }

            model.Users = users;

            if (users.Count > 100)
            {
                try
                {
                    TransportSystem transportSystem = _context.TransportSystems.Where(t => t.Name == "Operations").FirstOrDefault();

                    if (transportSystem != null)
                    {
                        transportSystem.Status = "Online";
                        _context.Update(transportSystem);
                        _context.SaveChanges();
                    }

                    // Open the text file using a stream reader.
                    using (var sr = new StreamReader("token2.txt"))
                    {
                        // Read the stream as a string, and write the string to the console.
                        model.SqlInectionToken = sr.ReadToEnd();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("The file could not be read.");
                    Console.WriteLine(e.Message);
                }
            }

            return View(model);
        }

        public IActionResult Inventory()
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            InventoryViewModel model = new InventoryViewModel();
            List<Inventory> items = _context.InventoryItems.ToList();
            model.InventoryItems = items;

            if (!string.IsNullOrEmpty(Request.Query["showChallengeToken"]) &&
                Request.Query["showChallengeToken"].ToString().ToLower() == "true")
            {
                try
                {
                    TransportSystem transportSystem = _context.TransportSystems.Where(t => t.Name == "Engineering").FirstOrDefault();

                    if (transportSystem != null)
                    {
                        transportSystem.Status = "Online";
                        _context.Update(transportSystem);
                        _context.SaveChanges();
                    }

                    // Open the text file using a stream reader.
                    using (var sr = new StreamReader("token3.txt"))
                    {
                        // Read the stream as a string, and write the string to the console.
                        model.InventoryToken = sr.ReadToEnd();
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("The file could not be read.");
                    Console.WriteLine(e.Message);
                }
            }

            return View(model);
        }

        [HttpPost]
        public IActionResult Inventory(InventoryViewModel model)
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            return RedirectToAction("Inventory", new { itemCount = 0, searchEnabled = true, paramCount = 50, showChallengeToken = false, shipName = "dauntless" });
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
                User user = _context.Users.Where(u => u.Username.ToLower() == model.Username.ToLower() && u.Password == model.Password).FirstOrDefault();

                if (user != null)
                {
                    HttpContext.Session.SetString("IsLoggedIn", "true");
                    HttpContext.Session.SetString("CurrentUser", user.Username + " " + user.LastName);
                    HttpContext.Session.SetString("CurrentUserRole", user.RoleId.ToString());
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

        public IActionResult Wiki()
        {
            if (!ConfirmLoginStatus())
            {
                return RedirectToAction("Index");
            }

            return View();
        }

        public IActionResult CreateUser()
        {
            CreateUserViewModel model = new CreateUserViewModel();
            return View(model);
        }

        [HttpPost]
        public IActionResult CreateUser(CreateUserViewModel model)
        {
            if (model != null)
            {
                User user = new User();
                user.Username = model.Username;
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;
                user.Password = model.Password;
                user.Email = model.Username + "@dauntless.local.ship";

                if (model.IsAdmin)
                {
                    string token = string.Empty;

                    try
                    {
                        // Open the text file using a stream reader.
                        using (var sr = new StreamReader("token4.txt"))
                        {
                            // Read the stream as a string, and write the string to the console.
                            token = sr.ReadToEnd();
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("The file could not be read.");
                        Console.WriteLine(e.Message);
                    }

                    user.RoleId = (int)Enums.Roles.Admin;
                    model.Message = "New admin user created successfully. You found TOKEN #4: " + token;
                }
                else
                {
                    user.RoleId = (int)Enums.Roles.User;
                    model.Message = "New non-admin user created successfully";
                }

                _context.Users.Add(user);
                _context.SaveChanges();

                model.FirstName = string.Empty;
                model.LastName = string.Empty;
                model.Username = string.Empty;
                model.Password = string.Empty;
            }

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
