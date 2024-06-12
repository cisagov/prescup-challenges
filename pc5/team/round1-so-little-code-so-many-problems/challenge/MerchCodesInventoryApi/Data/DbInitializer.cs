/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MerchCodesInventoryApi.Data.Models;
using System;
using System.Linq;

namespace MerchCodesInventoryApi.Data
{
    public class DbInitializer
    {
        public static void Initialize(MerchCodesContext context)
        {
            context.Database.EnsureCreated();

            if (context.InventoryItems.Any())
            {
                return;   // if there are any inventory items, DB has been seeded
            }

            var inventoryItems = new Inventory[]
            {
                new Inventory{Name="Crew care package", Description="", Count=4},
                new Inventory{Name="Wet trash bags", Description="", Count=60},
                new Inventory{Name="CDRA beds", Description="", Count=6},
                new Inventory{Name="CHeCS", Description="", Count=2},
                new Inventory{Name="AQM", Description="", Count=1},
                new Inventory{Name="RSP", Description="", Count=3},
                new Inventory{Name="Fundoscope", Description="", Count=1},
                new Inventory{Name="ARED ropes/lanyards", Description="", Count=12},
                new Inventory{Name="T2 turbo cable", Description="", Count=2},
                new Inventory{Name="FCE", Description="", Count=1},
                new Inventory{Name="3.0 AH battery", Description="", Count=4},
                new Inventory{Name="SMPA/charger kit", Description="", Count=1},
                new Inventory{Name="Hard drives", Description="", Count=5},
                new Inventory{Name="Medical case", Description="", Count=1},
                new Inventory{Name="Serial converter", Description="", Count=3},
                new Inventory{Name="TVIS gyro cable", Description="", Count=2},
                new Inventory{Name="Microflow", Description="", Count=1},
                new Inventory{Name="Biolab LSM Pumps", Description="", Count=4},
                new Inventory{Name="Double Cold Bags", Description="", Count=22},
                new Inventory{Name="HRP", Description="", Count=1},
                new Inventory{Name="BCAT", Description="", Count=3},
                new Inventory{Name="BRIC", Description="", Count=4},
                new Inventory{Name="CGBA ", Description="", Count=2},
                new Inventory{Name="FCF supplies", Description="", Count=2},
                new Inventory{Name="MSG gloves", Description="", Count=8},
                new Inventory{Name="SPHERES", Description="", Count=2},
                new Inventory{Name="VCAM", Description="", Count=1},
                new Inventory{Name="EXPRESS Rack Stowage Lockers", Description="", Count=2},
                new Inventory{Name="Surplus +4C Ice Bricks", Description="", Count=8},
                new Inventory{Name="Ion filter", Description="", Count=2},
                new Inventory{Name="Gloves", Description="", Count=60},
                new Inventory{Name="Wire tie caddy", Description="", Count=2},
                new Inventory{Name="REBA", Description="", Count=1},
                new Inventory{Name="ECOKs", Description="", Count=1},
                new Inventory{Name="CCAs", Description="", Count=1},
                new Inventory{Name="LCVGs", Description="", Count=1},
                new Inventory{Name="TEPC", Description="", Count=1},
                new Inventory{Name="Crank handle", Description="", Count=2},
                new Inventory{Name="GSCs", Description="", Count=3},
                new Inventory{Name="CSA-CP", Description="", Count=1},
                new Inventory{Name="CSA-O2", Description="", Count=1},
                new Inventory{Name="RAMs", Description="", Count=4},
                new Inventory{Name="IV Supply Pack", Description="", Count=30},
                new Inventory{Name="Top. & Inj. Medications Pack", Description="", Count=50},
                new Inventory{Name="Oral Meds Pack", Description="", Count=50},
                new Inventory{Name="ECLSS", Description="", Count=1},
                new Inventory{Name="H2 Sensor ORU", Description="", Count=2},
                new Inventory{Name="ACY Urine Filter Hose Assembly", Description="", Count=3},
                new Inventory{Name="Microbial Check Valve ORU", Description="", Count=4},
                new Inventory{Name="Control Panel", Description="", Count=1},
                new Inventory{Name="Pump Sep. ORU", Description="", Count=2},
                new Inventory{Name="Ion Exchange Bed", Description="", Count=2},
                new Inventory{Name="PBAs", Description="", Count=10},
                new Inventory{Name="HEPA Filters", Description="", Count=20},
                new Inventory{Name="Silver Biocide Kit", Description="", Count=4},
                new Inventory{Name="EPS", Description="", Count=1},
                new Inventory{Name="UOPs", Description="", Count=1},
                new Inventory{Name="RPCM III", Description="", Count=1},
                new Inventory{Name="RPCM V", Description="", Count=1},
                new Inventory{Name="TCTT", Description="", Count=1},
                new Inventory{Name="Particulate Filter ORUs", Description="", Count=7},
                new Inventory{Name="Double CTBs (Assy. Leftovers)", Description="", Count=3},
                new Inventory{Name="CCP & PMM Reloc. Equipment", Description="", Count=2},
                new Inventory{Name="Voltage and current stabilizer", Description="", Count=5}
            };

            foreach (Inventory i in inventoryItems)
            {
                context.InventoryItems.Add(i);
            }

            context.SaveChanges();
        }
    }
}

