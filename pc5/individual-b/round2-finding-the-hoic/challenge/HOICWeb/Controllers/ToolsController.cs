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
    public class ToolsController : Controller
    {
        private readonly ILogger<ToolsController> _logger;
        private readonly IWebHostEnvironment _env;

        public ToolsController(ILogger<ToolsController> logger, IWebHostEnvironment env)
        {
            _logger = logger;
            _env = env;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult DownloadHOIC()
        {
            if (Request.Cookies["loggedin"] == null || Request.Cookies["loggedin"] != "true")
            {
                return RedirectToAction("Index", new { Message = "You must be logged in to download the HOIC."});
            }

            byte[] fileBytes = System.IO.File.ReadAllBytes(Path.Combine(_env.ContentRootPath, "HOIC", "HOIC.zip"));
            return File(fileBytes, "application/force-download", "HOIC.zip");
        }
    }
}
