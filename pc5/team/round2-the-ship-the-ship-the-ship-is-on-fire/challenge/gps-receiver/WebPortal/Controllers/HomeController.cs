/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using WebPortal.Models;
using System.Text.RegularExpressions;

namespace WebPortal.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
        _logger = logger;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult GPS()
    {
        string coordinates = string.Empty;

        try
        {
            using (var sr = new StreamReader("/home/user/Documents/GPS.txt"))
            {
                coordinates = sr.ReadToEnd();
                coordinates = Regex.Replace(coordinates, @"\p{C}+", string.Empty);
                ViewBag.Coordinates = coordinates;
                Console.WriteLine(coordinates);
            }
        }
        catch (Exception exc)
        {
            Console.WriteLine(exc.Message);
        }

        if (coordinates.Contains("32.943241") && coordinates.Contains("-106.419533"))
        {
            try
            {
                using (var sr = new StreamReader("/home/user/Documents/GPSToken.txt"))
                {
                    ViewBag.GPSToken = sr.ReadToEnd();
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine(exc.Message);
            }             
        }

        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

