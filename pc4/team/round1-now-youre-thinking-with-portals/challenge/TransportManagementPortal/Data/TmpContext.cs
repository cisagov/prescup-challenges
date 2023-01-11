// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using TransportManagementPortal.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace TransportManagementPortal.Data
{
    public class TmpContext : DbContext
    {
        public TmpContext(DbContextOptions<TmpContext> options) : base(options)
        {
        }

        public DbSet<Inventory> InventoryItems { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<TransportSystem> TransportSystems { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<AppKey> AppKeys { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Inventory>().ToTable("Inventory");
            modelBuilder.Entity<Role>().ToTable("Role");
            modelBuilder.Entity<TransportSystem>().ToTable("TransportSystem");
            modelBuilder.Entity<User>().ToTable("User");
            modelBuilder.Entity<AppKey>().ToTable("AppKey");
        }
    }
}
