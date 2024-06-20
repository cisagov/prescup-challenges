/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using Microsoft.AspNetCore.Mvc;
using ManagementPortal.Data;
using ManagementPortal.Data.Models;

namespace ManagementPortal.Controllers
{
    public class NoRobotsController : Controller
    {
        public NoRobotsController()
        {
            
        }

        public IActionResult Index()
        {
            return View("Index");
        }

        public IActionResult Admin()
        {
            return View("Index");
        }

        public IActionResult Internal()
        {
            return View("Index");
        }

        public IActionResult Hidden()
        {
            return View("Index");
        }

        public IActionResult Management()
        {
            return View("Index");
        }
    }
}

