/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using ScadaWeb.Models;

namespace ScadaWeb.Data
{
    public class ScadaDbContext : DbContext
    {
        protected readonly IConfiguration Configuration;

        public ScadaDbContext(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // connect to postgres with connection string from app settings
            options.UseSqlite(Configuration.GetConnectionString("ScadaDatabaseConnection"));
        }

        public DbSet<ScadaWeb.Models.LogEntry> ScadaLogs { get; set; }
    }
}

