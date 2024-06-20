/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using HOICWeb.Models;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace HOICWeb.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _config;

        public HomeController(ILogger<HomeController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Login()
        {
            if (string.IsNullOrWhiteSpace(_config.GetValue<string>("SiteUser")) || 
                string.IsNullOrWhiteSpace(_config.GetValue<string>("Password")))
            {
                ViewBag.LoginEnabled = false;
                ViewBag.Message = "This is not the site you are looking for. Login has been disabled for this site.";
            }
            else
            {
                ViewBag.LoginEnabled = true;
            }

            return View();
        }

        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(_config.GetValue<string>("SiteUser")) ||
                string.IsNullOrWhiteSpace(_config.GetValue<string>("Password")))
            {
                ViewBag.LoginEnabled = false;
                ViewBag.Message = "This is not the site you are looking for. Login has been disabled for this site.";
                return View();
            }
            else
            {
                ViewBag.LoginEnabled = true;
            }

            var configUser = _config.GetValue<string>("SiteUser");
            var configPassword = _config.GetValue<string>("Password");

            if (username.ToLower() == configUser.ToLower() && password == configPassword)
            {
                // get values from config file
                Response.Cookies.Append("loggedin", "true");
                return RedirectToAction("Index");
            }
            else
            {
                ViewBag.Message = "Invalid email or password.";
                return View();
            }
        }

        public IActionResult Logout()
        {
            Response.Cookies.Delete("loggedin");
            return RedirectToAction("Index");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
