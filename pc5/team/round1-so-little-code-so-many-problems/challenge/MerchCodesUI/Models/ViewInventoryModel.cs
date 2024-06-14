/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesInventoryApi.Data.Models;

namespace MerchCodesUI.Models
{
    public class ViewInventoryModel
    {
        public List<Inventory> InventoryItems { get; set; }
        public string SearchTerm { get; set; }
        public string Message { get; set; }
    }
}

