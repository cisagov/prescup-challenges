/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesInventoryApi.Data;
using MerchCodesInventoryApi.Data.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System.Text;
using System.Text.Encodings.Web;

namespace MerchCodesInventoryApi.Controllers
{
    [ApiController]
    [Route("api/inventory")]
    public class InventoryController : Controller
    {
        private readonly ILogger<InventoryController> _logger;
        private readonly IConfiguration _configuration;
        private readonly MerchCodesContext _context;

        public InventoryController(ILogger<InventoryController> logger, IConfiguration configuration, MerchCodesContext context)
        {
            _logger = logger;
            _configuration = configuration;
            _context = context;
        }

        [HttpPost]
        [Route("EditInventoryItem")]
        public JsonResult EditInventoryItem([FromBody] Inventory inventory)
        {
            try
            {
                Inventory editItem = _context.InventoryItems.Where(i => i.Id == inventory.Id).FirstOrDefault();

                if (editItem == null)
                {
                    return Json(false);
                }

                _context.InventoryItems.Update(editItem);
                _context.SaveChanges();

                return Json(true);
            }
            catch (Exception)
            {
                return Json(false);
            }
        }

        [HttpPost]
        [Route("AddInventoryItem")]
        public JsonResult AddInventoryItem([FromBody] Inventory inventory)
        {
            try
            {
                _context.InventoryItems.Add(inventory);
                _context.SaveChanges();

                return Json(true);
            }
            catch (Exception)
            {
                return Json(false);
            }
        }

        /// <summary>
        /// TODO: Update this method to prevent sql injection attacks
        /// </summary>
        /// <param name="searchTerm"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("SearchInventory")]
        public JsonResult SearchInventory(string searchTerm)
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
            {
                return null;
            }

            List<Inventory> inventoryItems = new List<Inventory>();
            string constr = _configuration.GetConnectionString("DefaultConnection");

            using (NpgsqlConnection con = new NpgsqlConnection(constr))
            {
                string query = "select * from \"Inventory\" where \"Name\" like '%" + searchTerm + "%' or \"Description\" like '%" + searchTerm + "%'";
                using (NpgsqlCommand cmd = new NpgsqlCommand(query))
                {
                    cmd.Connection = con;
                    con.Open();

                    using (NpgsqlDataReader dr = cmd.ExecuteReader())
                    {
                        while (dr.Read())
                        {
                            inventoryItems.Add(new Inventory
                            {
                                Id = dr["Id"].ToString(),
                                Name = dr["Name"].ToString(),
                                Description = dr["Description"].ToString(),
                                Count = Convert.ToInt32(dr["Count"])
                            });
                        }
                    }
                }

                con.Close();
            }

            return Json(inventoryItems);
        }

        /// <summary>
        /// TODO: Update this method to html encode data to prevent script injection attacks
        /// </summary>
        /// <param name="inventory"></param>
        /// <returns></returns>
        [HttpGet]
        [Route("GetInventoryItems")]
        public JsonResult GetInventoryItems()
        {
            List<Inventory> inventoryItems = _context.InventoryItems.ToList();

            return Json(inventoryItems);
        }
    }
}

