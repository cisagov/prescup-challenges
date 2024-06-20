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
    public class DownloadsController : Controller
    {
        private readonly ILogger<DownloadsController> _logger;

        public DownloadsController(ILogger<DownloadsController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}
