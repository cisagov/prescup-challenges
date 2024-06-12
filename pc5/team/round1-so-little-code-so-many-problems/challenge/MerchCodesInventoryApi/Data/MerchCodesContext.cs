/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesInventoryApi.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace MerchCodesInventoryApi.Data
{
    public class MerchCodesContext : DbContext
    {
        public MerchCodesContext(DbContextOptions<MerchCodesContext> options) : base(options)
        {
        }

        public DbSet<Inventory> InventoryItems { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Inventory>().ToTable("Inventory");
        }
    }
}

