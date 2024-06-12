/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using ScadaWeb.Models;
using System;
using System.Linq;

namespace ScadaWeb.Data
{
    public class DbInitializer
    {
        public static void Initialize(ScadaDbContext context)
        {
            context.Database.EnsureCreated();

            if (context.ScadaLogs.Any())
            {
                return;   // DB has been seeded
            }

            context.ScadaLogs.AddRange(
                new LogEntry
                {
                    Id = "11111111-1111-1111-1111-111111111111",
                    Text = "Reactor 1 started by user tsmith@reactor.merch.codes.",
                    CreateDate = DateTime.UtcNow
                },
                new LogEntry
                {
                    Id = "22222222-2222-2222-2222-222222222222",
                    Text = "Reactor 2 started by user tsmith@reactor.merch.codes.",
                    CreateDate = DateTime.UtcNow
                },
                new LogEntry
                {
                    Id = "33333333-3333-3333-3333-333333333333",
                    Text = "Reactor 3 started by user tsmith@reactor.merch.codes.",
                    CreateDate = DateTime.UtcNow
                }
            );

            context.SaveChanges();
        }
    }
}


