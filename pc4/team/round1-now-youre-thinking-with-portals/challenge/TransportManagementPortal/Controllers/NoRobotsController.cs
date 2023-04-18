// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using Microsoft.AspNetCore.Mvc;
using TransportManagementPortal.Data;
using TransportManagementPortal.Data.Models;

namespace TransportManagementPortal.Controllers
{
    public class NoRobotsController : Controller
    {
        private readonly TmpContext _context;

        public NoRobotsController(TmpContext context)
        {
            _context = context;
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

        public IActionResult Network()
        {
            string token = string.Empty;

            try
            {
                TransportSystem transportSystem = _context.TransportSystems.Where(t => t.Name == "Communications").FirstOrDefault();

                if (transportSystem != null)
                {
                    transportSystem.Status = "Online";
                    _context.Update(transportSystem);
                    _context.SaveChanges();
                }

                // Open the text file using a stream reader.
                using (var sr = new StreamReader("token1.txt"))
                {
                    // Read the stream as a string, and write the string to the console.
                    token = sr.ReadToEnd();
                }
            }
            catch (IOException e)
            {
                Console.WriteLine("The file could not be read:");
                Console.WriteLine(e.Message);
            }

            ViewBag.Token = token;

            return View();
        }
    }
}
