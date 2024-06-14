/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesInventoryApi.Data.Models;
using MerchCodesUI.Models;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Diagnostics.Contracts;
using System;
using System.Net.Http;
using static System.Net.Mime.MediaTypeNames;
using System.Runtime.Intrinsics.X86;
using System.Net.Http.Headers;
using System.Text;

namespace MerchCodesUI.Controllers
{
    public class InventoryController : BaseController
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IConfiguration _configuration;

        public InventoryController(ILogger<HomeController> logger, IConfiguration configuration) : base(configuration)
        {
            _logger = logger;
            _configuration = configuration;
            AddAuthenticationHeaders();
        }

        public async Task<IActionResult> Index()
        {
            ViewInventoryModel viewInventoryModel = new ViewInventoryModel();
            var result = await httpClient.GetAsync(_configuration.GetValue<string>("ApiUrl") + "api/inventory/getinventoryitems");
            var jsonString = await result.Content.ReadAsStringAsync();
            viewInventoryModel.InventoryItems = JsonConvert.DeserializeObject<List<Inventory>>(jsonString);

            return View(viewInventoryModel);
        }

        [HttpGet]
        public async Task<IActionResult> SearchInventory()
        {
            ViewInventoryModel viewInventoryModel = new ViewInventoryModel();
            return View(viewInventoryModel);
        }

        [HttpPost]
        public async Task<IActionResult> SearchInventory(string searchTerm)
        {
            ViewInventoryModel viewInventoryModel = new ViewInventoryModel();

            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                ViewBag.Message = "Please enter a search term.";
                return View(viewInventoryModel);
            }

            var result = await httpClient.GetAsync(_configuration.GetValue<string>("ApiUrl") + "api/inventory/searchinventory?searchTerm=" + searchTerm);
            var jsonString = await result.Content.ReadAsStringAsync();
            var inventoryItems = JsonConvert.DeserializeObject<List<Inventory>>(jsonString);

            if (inventoryItems == null)
            {
                ViewBag.Message = "An error was encountered. Please refresh the page and try again";
            }
            else if (inventoryItems.Count == 0)
            {
                ViewBag.Message = "There were no results for that search term.";
            }
            else
            {
                viewInventoryModel.InventoryItems = inventoryItems;
            }

            return View(viewInventoryModel);
        }

        [HttpGet]
        public IActionResult AddInventory()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> AddInventory(string name, string description, string count)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(count))
            {
                ViewBag.Message = "Name and Count are required fields";
                return View();
            }

            Inventory inventory = new Inventory();
            inventory.Name = name ?? string.Empty;
            inventory.Description = description ?? string.Empty;
            inventory.Count = Convert.ToInt32(count ?? "0");

            var content = JsonConvert.SerializeObject(inventory);
            var requestContent = new StringContent(content, Encoding.UTF8, "application/json");

            var response = await httpClient.PostAsync(_configuration.GetValue<string>("ApiUrl") + "api/inventory/addinventoryitem", requestContent);
            string result = response.Content.ReadAsStringAsync().Result;

            if (result == "true")
            {
                ViewBag.Message = "Inventory item added successfully";
                return View();
            }
            else
            {
                ViewBag.Message = "Error adding inventory item";
                return View();
            }
        }
    }
}

