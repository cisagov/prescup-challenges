using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using PoolWeb.Models;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;


namespace PoolWeb.Controllers;

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
        IndexViewModel model = new IndexViewModel();

        if (IsUserLoggedIn())
        {
            using (var sr = new StreamReader("token1.txt"))
            {
                model.Token1 = sr.ReadToEnd();
            }
        }

        return View(model);
    }

    public IActionResult Facilities()
    {
        return View();
    }

    public IActionResult HoursPricing()
    {
        return View();
    }

    public IActionResult OurTeam()
    {
        return View();
    }

    public IActionResult ContactUs()
    {
        return View();
    }

    public IActionResult ViewCameras()
    {
        CameraViewModel model = new CameraViewModel();
        model.SecurityToken = _config.GetValue<string>("SecurityToken");
        string apiurl = _config.GetValue<string>("APIImageUrl");
        HttpClient _sharedClient = new HttpClient();
        string cameraStatus = "";

        //model.Message = model.Message + Environment.NewLine + "Security Token: " +  model.SecurityToken;
        //model.Message = model.Message + Environment.NewLine + "APIImageUrl: " + apiurl;

        try
        {
            using (HttpResponseMessage response = _sharedClient.GetAsync(apiurl + "api/getcamerastatus?securityToken=" + model.SecurityToken).Result)
            {
                var httpResponse = response.Content.ReadAsStringAsync().Result;
                cameraStatus = httpResponse;
            }

            if (cameraStatus.Contains("enabled"))
            {
                model.ImagePath1 = apiurl + "StaticFiles/6e19cc19829a4ff89eb54bf5a979c5cd.jpg";
                model.ImagePath2 = apiurl + "StaticFiles/794ac710948f4b90b7b22743650dde11.jpg";
                model.ImagePath3 = apiurl + "StaticFiles/d42d6b758fce495a9ac9e32466704c2f.jpg";
                model.ImagePath4 = apiurl + "StaticFiles/4c4c2b739c4b4c9eb864540cf2423bda.jpg";
                model.ImagePath5 = apiurl + "StaticFiles/74e0cc74c8be4679a9c917edb9987d02.jpg";
            }
            else
            {
                //model.Message = model.Message + Environment.NewLine + "CameraStatus: " + cameraStatus;
            }

            if (cameraStatus.Contains("disabled"))
            {
                using (var sr = new StreamReader("token3.txt"))
                {
                    model.Token3 = sr.ReadToEnd();
                }
            }
        }
        catch (Exception exc)
        {
            model.Message = model.Message + Environment.NewLine + exc.Message + Environment.NewLine + exc.StackTrace;
        }

        return View(model);
    }

    [HttpPost]
    public IActionResult ContactUs(string name, string message)
    {
        ViewBag.Message = "Thank you for contacting us. We will respond within 24 hours.";
        return View();
    }

    public IActionResult Admin()
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Index");
        }

        return View();
    }

    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Login(string username, string password)
    {
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

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    private bool IsUserLoggedIn()
    {
        if (Request.Cookies["loggedin"] == null || Request.Cookies["loggedin"] != "true")
        {
            return false;
        }
        else
        {
            return true;
        }
    }
}
