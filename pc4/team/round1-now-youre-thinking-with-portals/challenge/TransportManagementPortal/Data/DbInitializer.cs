// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using TransportManagementPortal.Data.Models;
using System;
using System.Linq;

namespace TransportManagementPortal.Data
{
    public class DbInitializer
    {
        public static void Initialize(TmpContext context)
        {
            context.Database.EnsureCreated();

            if (context.Users.Any())
            {
                return;   // if there are any users, DB has been seeded
            }

            var roles = new Role[]
            {
                new Role{Id=1, RoleName="User"},
                new Role{Id=2, RoleName="Developer"},
                new Role{Id=3, RoleName="Reporter"},
                new Role{Id=4, RoleName="Custodian"},
                new Role{Id=5, RoleName="CreateUser"},
                new Role{Id=6, RoleName="Admin"}
            };

            foreach (Role r in roles)
            {
                context.Roles.Add(r);
            }

            context.SaveChanges();

            var users = new User[]
            {
                new User{Username="rwilco", Password="sanitation", FirstName="Roger", LastName="Wilco", Email="rwilco@dauntless.local.ship", RoleId=4},
                new User{Username="dbrown", Password="vQ!*8Tz6iW", FirstName="Dawn", LastName="Brown", Email="dbrown@dauntless.local.ship", RoleId=2},
                new User{Username="lfisher", Password="+KLm9Jf8Tj", FirstName="Linda", LastName="Fisher", Email="lfisher@dauntless.local.ship", RoleId=1},
                new User{Username="mswanson", Password="_tJ0XMnFab", FirstName="Michael", LastName="Swanson", Email="mswanson@dauntless.local.ship", RoleId=3},
                new User{Username="darmstrong", Password="&WVGiKH2b1", FirstName="Daniel", LastName="Armstrong", Email="darmstrong@dauntless.local.ship", RoleId=3},
                new User{Username="jtaylor", Password=")N*p8DtG$F", FirstName="Jennifer", LastName="Taylor", Email="jtaylor@dauntless.local.ship", RoleId=3},
                new User{Username="bgarrison", Password="r(U4Tzzvc&", FirstName="Brandi", LastName="Garrison", Email="bgarrison@dauntless.local.ship", RoleId=1},
                new User{Username="bmaxwell", Password=")7rfPeQr#y", FirstName="Brad", LastName="Maxwell", Email="bmaxwell@dauntless.local.ship", RoleId=1},
                new User{Username="jchavez", Password="7J#s6J^k(i", FirstName="Julie", LastName="Chavez", Email="jchavez@dauntless.local.ship", RoleId=1},
                new User{Username="kwest", Password="Gb2NPmR2%Q", FirstName="Kevin", LastName="West", Email="kwest@dauntless.local.ship", RoleId=1},
                new User{Username="rfranklin", Password="vb0Px*9e5#", FirstName="Richard", LastName="Franklin", Email="rfranklin@dauntless.local.ship", RoleId=3},
                new User{Username="mjohnson", Password="U+9u+Oy#c%", FirstName="Michael", LastName="Johnson", Email="mjohnson@dauntless.local.ship", RoleId=3},
                new User{Username="amckee", Password="w^4XV#$ls8", FirstName="Adam", LastName="Mckee", Email="amckee@dauntless.local.ship", RoleId=2},
                new User{Username="tarnold", Password="!g4C9Co0o1", FirstName="Tammy", LastName="Arnold", Email="tarnold@dauntless.local.ship", RoleId=3},
                new User{Username="aevans", Password="U4@7%YlGk^", FirstName="Alicia", LastName="Evans", Email="aevans@dauntless.local.ship", RoleId=2},
                new User{Username="cbradley", Password="OoQD94BK)9", FirstName="Charles", LastName="Bradley", Email="cbradley@dauntless.local.ship", RoleId=3},
                new User{Username="cmyers", Password="Pl&Nx#u9)1", FirstName="Cindy", LastName="Myers", Email="cmyers@dauntless.local.ship", RoleId=3},
                new User{Username="dmiller", Password="#sC9#Vtg7z", FirstName="Diana", LastName="Miller", Email="dmiller@dauntless.local.ship", RoleId=1},
                new User{Username="bdixon", Password="f+fUH*SI@5", FirstName="Brittany", LastName="Dixon", Email="bdixon@dauntless.local.ship", RoleId=2},
                new User{Username="ccraig", Password="_j&7hD(n*0", FirstName="Claudia", LastName="Craig", Email="ccraig@dauntless.local.ship", RoleId=3},
                new User{Username="jhall", Password="c&6*5HnHAb", FirstName="Jason", LastName="Hall", Email="jhall@dauntless.local.ship", RoleId=2},
                new User{Username="jdiaz", Password="79w8Nu&mD$", FirstName="Jacqueline", LastName="Diaz", Email="jdiaz@dauntless.local.ship", RoleId=2},
                new User{Username="phuff", Password="A+8t8SaM%s", FirstName="Patricia", LastName="Huff", Email="phuff@dauntless.local.ship", RoleId=3},
                new User{Username="mwalls", Password="%XX1zJmq)_", FirstName="Matthew", LastName="Walls", Email="mwalls@dauntless.local.ship", RoleId=2},
                new User{Username="jcoleman", Password="+y&GzQg9B5", FirstName="Jason", LastName="Coleman", Email="jcoleman@dauntless.local.ship", RoleId=2},
                new User{Username="epierce", Password="$d8)YMgz&f", FirstName="Eric", LastName="Pierce", Email="epierce@dauntless.local.ship", RoleId=3},
                new User{Username="tmartinez", Password="A_w9#vItYO", FirstName="Todd", LastName="Martinez", Email="tmartinez@dauntless.local.ship", RoleId=3},
                new User{Username="djackson", Password="_fkQ+v0u08", FirstName="Daniel", LastName="Jackson", Email="djackson@dauntless.local.ship", RoleId=2},
                new User{Username="csmith", Password="qy1BRLpO!B", FirstName="Christopher", LastName="Smith", Email="csmith@dauntless.local.ship", RoleId=3},
                new User{Username="eturner", Password=")4VT0*^sYy", FirstName="Ernest", LastName="Turner", Email="eturner@dauntless.local.ship", RoleId=2},
                new User{Username="aross", Password="jx)9JHrD%^", FirstName="Ashley", LastName="Ross", Email="aross@dauntless.local.ship", RoleId=3},
                new User{Username="esherman", Password="undaunted", FirstName="Emily", LastName="Sherman", Email="esherman@dauntless.local.ship", RoleId=5},
                new User{Username="hjohnson", Password="U+p70)OgA@", FirstName="Heather", LastName="Johnson", Email="hjohnson@dauntless.local.ship", RoleId=1},
                new User{Username="tsmith", Password="^!d%n8Uwn+", FirstName="Timothy", LastName="Smith", Email="tsmith@dauntless.local.ship", RoleId=3},
                new User{Username="jyoung", Password="m*9CI!Bma_", FirstName="Jay", LastName="Young", Email="jyoung@dauntless.local.ship", RoleId=3},
                new User{Username="dpierce", Password="^PRBhpg^05", FirstName="Daniel", LastName="Pierce", Email="dpierce@dauntless.local.ship", RoleId=3},
                new User{Username="llynch", Password="#nbxPStc1H", FirstName="Luis", LastName="Lynch", Email="llynch@dauntless.local.ship", RoleId=1},
                new User{Username="jwilliams", Password="R$3O3bsqEZ", FirstName="James", LastName="Williams", Email="jwilliams@dauntless.local.ship", RoleId=3},
                new User{Username="khaynes", Password="%@2@C_Rbgv", FirstName="Kimberly", LastName="Haynes", Email="khaynes@dauntless.local.ship", RoleId=3},
                new User{Username="rkramer", Password="i^D!1sy)gS", FirstName="Ryan", LastName="Kramer", Email="rkramer@dauntless.local.ship", RoleId=2},
                new User{Username="azhang", Password="9ADczyIu@H", FirstName="Amanda", LastName="Zhang", Email="azhang@dauntless.local.ship", RoleId=3},
                new User{Username="ewilson", Password="G#9_CRy_&a", FirstName="Elizabeth", LastName="Wilson", Email="ewilson@dauntless.local.ship", RoleId=3},
                new User{Username="ahogan", Password="3eK&cQna*+", FirstName="Aaron", LastName="Hogan", Email="ahogan@dauntless.local.ship", RoleId=2},
                new User{Username="rmartin", Password="!J75L!sN5W", FirstName="Richard", LastName="Martin", Email="rmartin@dauntless.local.ship", RoleId=3},
                new User{Username="treed", Password="nu2NcgYPG(", FirstName="Tyler", LastName="Reed", Email="treed@dauntless.local.ship", RoleId=1},
                new User{Username="apatton", Password="8)(3QMrQ*u", FirstName="Anna", LastName="Patton", Email="apatton@dauntless.local.ship", RoleId=3},
                new User{Username="sadkins", Password="AD%N0O+i8w", FirstName="Sarah", LastName="Adkins", Email="sadkins@dauntless.local.ship", RoleId=2},
                new User{Username="adixon", Password="3q_h3MNwgE", FirstName="Alan", LastName="Dixon", Email="adixon@dauntless.local.ship", RoleId=2},
                new User{Username="sparker", Password="!v7B)lS&Wy", FirstName="Steven", LastName="Parker", Email="sparker@dauntless.local.ship", RoleId=2},
                new User{Username="sperez", Password="0b#i1G(vLZ", FirstName="Stephanie", LastName="Perez", Email="sperez@dauntless.local.ship", RoleId=2},
                new User{Username="rbrown", Password="$14NFo)a92", FirstName="Ronald", LastName="Brown", Email="rbrown@dauntless.local.ship", RoleId=3},
                new User{Username="sjones", Password="tz86uH)v)P", FirstName="Samantha", LastName="Jones", Email="sjones@dauntless.local.ship", RoleId=2},
                new User{Username="mperez", Password="xXGPoVzu!0", FirstName="Matthew", LastName="Perez", Email="mperez@dauntless.local.ship", RoleId=2},
                new User{Username="projas", Password="$$mt4PJaHO", FirstName="Patricia", LastName="Rojas", Email="projas@dauntless.local.ship", RoleId=3},
                new User{Username="mwilliams", Password="A#G8D!fc_g", FirstName="Manuel", LastName="Williams", Email="mwilliams@dauntless.local.ship", RoleId=3},
                new User{Username="churst", Password="+6Fx^EBSds", FirstName="Christopher", LastName="Hurst", Email="churst@dauntless.local.ship", RoleId=3},
                new User{Username="nmiller", Password="#GLaxuf247", FirstName="Nicholas", LastName="Miller", Email="nmiller@dauntless.local.ship", RoleId=2},
                new User{Username="lcunningham", Password="*G8K7zFJb&", FirstName="Laura", LastName="Cunningham", Email="lcunningham@dauntless.local.ship", RoleId=2},
                new User{Username="kmoore", Password="n7cPg!%W%G", FirstName="Kimberly", LastName="Moore", Email="kmoore@dauntless.local.ship", RoleId=3},
                new User{Username="rmontgomery", Password="*p8fNPg)Lz", FirstName="Robert", LastName="Montgomery", Email="rmontgomery@dauntless.local.ship", RoleId=3},
                new User{Username="elopez", Password="P^&l5nVg(M", FirstName="Elizabeth", LastName="Lopez", Email="elopez@dauntless.local.ship", RoleId=2},
                new User{Username="lmckee", Password="^hVYEHAM(0", FirstName="Lisa", LastName="Mckee", Email="lmckee@dauntless.local.ship", RoleId=2},
                new User{Username="jcarter", Password="vg0GsY6xV$", FirstName="Julie", LastName="Carter", Email="jcarter@dauntless.local.ship", RoleId=2},
                new User{Username="ngomez", Password="kk09hJZRn*", FirstName="Nicholas", LastName="Gomez", Email="ngomez@dauntless.local.ship", RoleId=3},
                new User{Username="jboyd", Password="_6@&AX)dtt", FirstName="Jill", LastName="Boyd", Email="jboyd@dauntless.local.ship", RoleId=3},
                new User{Username="kdavidson", Password="JbD0CajuM^", FirstName="Kyle", LastName="Davidson", Email="kdavidson@dauntless.local.ship", RoleId=2},
                new User{Username="egriffith", Password="kVe9VcGX*&", FirstName="Eric", LastName="Griffith", Email="egriffith@dauntless.local.ship", RoleId=2},
                new User{Username="jchen", Password="$U1K0MgDPW", FirstName="Jack", LastName="Chen", Email="jchen@dauntless.local.ship", RoleId=3},
                new User{Username="jpadilla", Password="!$MRZtJDx5", FirstName="Julie", LastName="Padilla", Email="jpadilla@dauntless.local.ship", RoleId=3},
                new User{Username="jschroeder", Password="%1uP_)fvk^", FirstName="Joshua", LastName="Schroeder", Email="jschroeder@dauntless.local.ship", RoleId=2},
                new User{Username="rlawson", Password="*P%To$ajy2", FirstName="Robert", LastName="Lawson", Email="rlawson@dauntless.local.ship", RoleId=2},
                new User{Username="bruiz", Password="#4DLKUzIp1", FirstName="Betty", LastName="Ruiz", Email="bruiz@dauntless.local.ship", RoleId=3},
                new User{Username="ksantana", Password="^+^1HpeGwL", FirstName="Kristin", LastName="Santana", Email="ksantana@dauntless.local.ship", RoleId=1},
                new User{Username="nrice", Password="%2!G(Qoe#O", FirstName="Nicole", LastName="Rice", Email="nrice@dauntless.local.ship", RoleId=3},
                new User{Username="tday", Password="N2+^dF(M$i", FirstName="Tammy", LastName="Day", Email="tday@dauntless.local.ship", RoleId=1},
                new User{Username="vcox", Password="_gj8+6GaY4", FirstName="Victoria", LastName="Cox", Email="vcox@dauntless.local.ship", RoleId=1},
                new User{Username="jcollins", Password="w1YBJ!(H!G", FirstName="John", LastName="Collins", Email="jcollins@dauntless.local.ship", RoleId=1},
                new User{Username="cbartlett", Password="%3*9)GstOk", FirstName="Christine", LastName="Bartlett", Email="cbartlett@dauntless.local.ship", RoleId=2},
                new User{Username="erodriguez", Password="(iF2tHylUF", FirstName="Elizabeth", LastName="Rodriguez", Email="erodriguez@dauntless.local.ship", RoleId=3},
                new User{Username="rkelly", Password="#ABIy)0HK5", FirstName="Richard", LastName="Kelly", Email="rkelly@dauntless.local.ship", RoleId=3},
                new User{Username="ablevins", Password="3@W2CDnbW^", FirstName="Angela", LastName="Blevins", Email="ablevins@dauntless.local.ship", RoleId=1},
                new User{Username="tparker", Password="vh!v2C9kEE", FirstName="Tyler", LastName="Parker", Email="tparker@dauntless.local.ship", RoleId=1},
                new User{Username="sdavis", Password="Rx1lPHK3*4", FirstName="Sarah", LastName="Davis", Email="sdavis@dauntless.local.ship", RoleId=3},
                new User{Username="dfranco", Password="O!xa8Gi7UR", FirstName="Dana", LastName="Franco", Email="dfranco@dauntless.local.ship", RoleId=2},
                new User{Username="agonzalez", Password="s%D7TrE7Z!", FirstName="Ana", LastName="Gonzalez", Email="agonzalez@dauntless.local.ship", RoleId=1},
                new User{Username="mlopez", Password="lBO7WRanO_", FirstName="Monica", LastName="Lopez", Email="mlopez@dauntless.local.ship", RoleId=3},
                new User{Username="cgraham", Password="32HW7UPx%_", FirstName="Cassandra", LastName="Graham", Email="cgraham@dauntless.local.ship", RoleId=3},
                new User{Username="blawson", Password="^D&7CKfO6o", FirstName="Bryan", LastName="Lawson", Email="blawson@dauntless.local.ship", RoleId=2},
                new User{Username="smartin", Password="k0Mb$e(y^Y", FirstName="Scott", LastName="Martin", Email="smartin@dauntless.local.ship", RoleId=3},
                new User{Username="cnelson", Password="$)p7Vocp%7", FirstName="Crystal", LastName="Nelson", Email="cnelson@dauntless.local.ship", RoleId=1},
                new User{Username="ahall", Password="aM1pSia@%o", FirstName="Amber", LastName="Hall", Email="ahall@dauntless.local.ship", RoleId=1},
                new User{Username="salexander", Password="C_3zsrMpw&", FirstName="Stephen", LastName="Alexander", Email="salexander@dauntless.local.ship", RoleId=2},
                new User{Username="tmadden", Password="EDB3LbQs&D", FirstName="Tiffany", LastName="Madden", Email="tmadden@dauntless.local.ship", RoleId=2},
                new User{Username="bmckinney", Password="DvPoe%jw^8", FirstName="Brooke", LastName="Mckinney", Email="bmckinney@dauntless.local.ship", RoleId=3},
                new User{Username="snoble", Password="+58CYLwj3e", FirstName="Samantha", LastName="Noble", Email="snoble@dauntless.local.ship", RoleId=1},
                new User{Username="loneill", Password="%KNQH8MkY6", FirstName="Lindsey", LastName="Oneill", Email="loneill@dauntless.local.ship", RoleId=2},
                new User{Username="rnguyen", Password="6XhQY*gm_U", FirstName="Robin", LastName="Nguyen", Email="rnguyen@dauntless.local.ship", RoleId=2},
                new User{Username="bscott", Password="+2KRu3fk0c", FirstName="Barbara", LastName="Scott", Email="bscott@dauntless.local.ship", RoleId=3},
                new User{Username="tshea", Password="8&IQ1MdgyH", FirstName="Timothy", LastName="Shea", Email="tshea@dauntless.local.ship", RoleId=2},
                new User{Username="dconrad", Password="ICj99grs3_", FirstName="David", LastName="Conrad", Email="dconrad@dauntless.local.ship", RoleId=2},
                new User{Username="jballard", Password="7ICXqGEp(C", FirstName="Jessica", LastName="Ballard", Email="jballard@dauntless.local.ship", RoleId=2}
            };

            foreach (User u in users)
            {
                context.Users.Add(u);
            }

            context.SaveChanges();

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
                new Inventory{Name="CD case", Description="", Count=1},
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

            var transportSystems = new TransportSystem[]
            {
                new TransportSystem{Name="Shuttle", Description="Fuel", Status="Online"},
                new TransportSystem{Name="Operations", Description="Personnel", Status="Offline"},
                new TransportSystem{Name="Communications", Description="Search", Status="Offline"},
                new TransportSystem{Name="Engineering", Description="Inventory", Status="Offline"},
                new TransportSystem{Name="Damage Control", Description="Management API", Status="Offline"},
                new TransportSystem{Name="Piloting and Navigation", Description="Location", Status="Online"}
            };

            foreach (TransportSystem ts in transportSystems)
            {
                context.TransportSystems.Add(ts);
            }

            var appkeys = new AppKey[]
            {
                new AppKey{ KeyType = "API", IsAvailable = false }
            };

            foreach (AppKey k in appkeys)
            {
                context.AppKeys.Add(k);
            }

            context.SaveChanges();
        }
    }
}
