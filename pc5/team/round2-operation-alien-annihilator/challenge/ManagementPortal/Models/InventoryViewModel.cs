/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using ManagementPortal.Data.Models;

namespace ManagementPortal.Models
{
    public class InventoryViewModel
    {
        public List<Inventory> InventoryItems { get; set; }
        public string Message { get; set; }
        public string InventoryToken { get; set; }
        public string SearchTerm { get; set; }
    }
}

