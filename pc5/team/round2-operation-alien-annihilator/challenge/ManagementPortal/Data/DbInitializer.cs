/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System;
using System.Linq;
using ManagementPortal.Data;
using ManagementPortal.Data.Models;
using ManagementPortal.Models;
using ManagementPortal.Services;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Linq;

namespace ManagementPortal.Data
{
    public class DbInitializer
    {
        public async static void Initialize(UsersService usersService, InventoryService inventoryService)
        {
            if (usersService.GetAsync().Result.Count == 0)
            {
                var users = new User[]
                {
                    new User{Username="rwilco", Password="zr7rxfaamly2-zk", FirstName="Roger", LastName="Wilco", Email="rwilco@merch.codes", RoleId=2},
                    new User{Username="dbrown", Password="uzNwbzld5isiiau", FirstName="Dawn", LastName="Brown", Email="dbrown@merch.codes", RoleId=3},
                    new User{Username="lfisher", Password="Ay(YIGHES!Y%SEG", FirstName="Linda", LastName="Fisher", Email="lfisher@merch.codes", RoleId=2},
                    new User{Username="mswanson", Password="Mj-byy2dke2mgfO", FirstName="Michael", LastName="Swanson", Email="mswanson@merch.codes", RoleId=2},
                    new User{Username="darmstrong", Password="eRNRB#HRAcs5uyq", FirstName="Daniel", LastName="Armstrong", Email="darmstrong@merch.codes", RoleId=2},
                    new User{Username="jtaylor", Password="ATmg3hqYFlabBzp", FirstName="Jennifer", LastName="Taylor", Email="jtaylor@merch.codes", RoleId=2},
                    new User{Username="bgarrison", Password="fOmouzusluc9kbc", FirstName="Brandi", LastName="Garrison", Email="bgarrison@merch.codes", RoleId=1},
                    new User{Username="bmaxwell", Password="cxhh%jlfflcipoh", FirstName="Brad", LastName="Maxwell", Email="bmaxwell@merch.codes", RoleId=3},
                    new User{Username="jchavez", Password="nP47lwq-zynq1m-", FirstName="Julie", LastName="Chavez", Email="jchavez@merch.codes", RoleId=2},
                    new User{Username="kwest", Password="w_Xfvyfhglkqwt6", FirstName="Kevin", LastName="West", Email="kwest@merch.codes", RoleId=2},
                    new User{Username="rfranklin", Password="tAbaK5ru8nul7w4", FirstName="Richard", LastName="Franklin", Email="rfranklin@merch.codes", RoleId=2},
                    new User{Username="mjohnson", Password="pdgWfyasizyuhhu", FirstName="Michael", LastName="Johnson", Email="mjohnson@merch.codes", RoleId=2},
                    new User{Username="amckee", Password="6vpcoB)gv-oduah", FirstName="Adam", LastName="Mckee", Email="amckee@merch.codes", RoleId=2},
                    new User{Username="tarnold", Password="anjVmoTflpjcuyg", FirstName="Tammy", LastName="Arnold", Email="tarnold@merch.codes", RoleId=3},
                    new User{Username="aevans", Password="Ujdtemmveaxc05w", FirstName="Alicia", LastName="Evans", Email="aevans@merch.codes", RoleId=2},
                    new User{Username="cbradley", Password="2tVibrmfxzmzuno", FirstName="Charles", LastName="Bradley", Email="cbradley@merch.codes", RoleId=2},
                    new User{Username="cmyers", Password="TTmialbtqleqpkz", FirstName="Cindy", LastName="Myers", Email="cmyers@merch.codes", RoleId=2},
                    new User{Username="dmiller", Password="Kjuypp3mmAAUCSP", FirstName="Diana", LastName="Miller", Email="dmiller@merch.codes", RoleId=3},
                    new User{Username="bdixon", Password="UgivTDM1zZKZRj(", FirstName="Brittany", LastName="Dixon", Email="bdixon@merch.codes", RoleId=2},
                    new User{Username="ccraig", Password="u0nFrNQaOhUw-ff", FirstName="Claudia", LastName="Craig", Email="ccraig@merch.codes", RoleId=2},
                    new User{Username="jhall", Password="i03Chms^B^XO!bt", FirstName="Jason", LastName="Hall", Email="jhall@merch.codes", RoleId=3},
                    new User{Username="jdiaz", Password="era%3Sv5gc0rntw", FirstName="Jacqueline", LastName="Diaz", Email="jdiaz@merch.codes", RoleId=2},
                    new User{Username="phuff", Password="949vxkzwpyorw34", FirstName="Patricia", LastName="Huff", Email="phuff@merch.codes", RoleId=2},
                    new User{Username="mwalls", Password="Yjvchr0flasvlpo", FirstName="Matthew", LastName="Walls", Email="mwalls@merch.codes", RoleId=3},
                    new User{Username="jcoleman", Password="QRSBXEMSAGOSTRg", FirstName="Jason", LastName="Coleman", Email="jcoleman@merch.codes", RoleId=2},
                    new User{Username="epierce", Password="1ant4(Czz5BOxOO", FirstName="Eric", LastName="Pierce", Email="epierce@merch.codes", RoleId=2},
                    new User{Username="tmartinez", Password="JLbksjlfd0qjl9U", FirstName="Todd", LastName="Martinez", Email="tmartinez@merch.codes", RoleId=2},
                    new User{Username="djackson", Password="V-lWM-w97prl8db", FirstName="Daniel", LastName="Jackson", Email="djackson@merch.codes", RoleId=2},
                    new User{Username="csmith", Password="nbkXBjovnslg-nx", FirstName="Christopher", LastName="Smith", Email="csmith@merch.codes", RoleId=2},
                    new User{Username="eturner", Password="GlinPBhj6owcg-e", FirstName="Ernest", LastName="Turner", Email="eturner@merch.codes", RoleId=3},
                    new User{Username="aross", Password="lKZDNR!Y&D(QWsq", FirstName="Ashley", LastName="Ross", Email="aross@merch.codes", RoleId=2},
                    new User{Username="esherman", Password="hmaytij7y32cpmq", FirstName="Emily", LastName="Sherman", Email="esherman@merch.codes", RoleId=2},
                    new User{Username="hjohnson", Password="mquqq2jd3wyj0d9", FirstName="Heather", LastName="Johnson", Email="hjohnson@merch.codes", RoleId=2},
                    new User{Username="tsmith", Password="xJHPZRLBn75bv8c", FirstName="Timothy", LastName="Smith", Email="tsmith@merch.codes", RoleId=2},
                    new User{Username="jyoung", Password="*SOU_2vn99bwqq2", FirstName="Jay", LastName="Young", Email="jyoung@merch.codes", RoleId=3},
                    new User{Username="dpierce", Password="AWHJYFlYz$5-gpp", FirstName="Daniel", LastName="Pierce", Email="dpierce@merch.codes", RoleId=2},
                    new User{Username="llynch", Password="dcvcwl-bw-3bd7s", FirstName="Luis", LastName="Lynch", Email="llynch@merch.codes", RoleId=2},
                    new User{Username="jwilliams", Password="M1!mNyyqun2paqw", FirstName="James", LastName="Williams", Email="jwilliams@merch.codes", RoleId=2},
                    new User{Username="khaynes", Password="lXf@W%vrsssiiw4", FirstName="Kimberly", LastName="Haynes", Email="khaynes@merch.codes", RoleId=3},
                    new User{Username="rkramer", Password="w63zovd1q0vcu8r", FirstName="Ryan", LastName="Kramer", Email="rkramer@merch.codes", RoleId=2},
                    new User{Username="azhang", Password="KT&3zc5t%VMIbXC", FirstName="Amanda", LastName="Zhang", Email="azhang@merch.codes", RoleId=2},
                    new User{Username="ewilson", Password="pmpjAqv15uyozbd", FirstName="Elizabeth", LastName="Wilson", Email="ewilson@merch.codes", RoleId=2},
                    new User{Username="ahogan", Password="lokaJondvjmx59M", FirstName="Aaron", LastName="Hogan", Email="ahogan@merch.codes", RoleId=2},
                    new User{Username="rmartin", Password="NKbtj*jcdkF*LTk", FirstName="Richard", LastName="Martin", Email="rmartin@merch.codes", RoleId=2},
                    new User{Username="treed", Password="d4ausntCBRIN2yt", FirstName="Tyler", LastName="Reed", Email="treed@merch.codes", RoleId=2},
                    new User{Username="apatton", Password="znMfprrsvMBwWLm", FirstName="Anna", LastName="Patton", Email="apatton@merch.codes", RoleId=3},
                    new User{Username="sadkins", Password="e1BHDt*tlylasbr", FirstName="Sarah", LastName="Adkins", Email="sadkins@merch.codes", RoleId=2},
                    new User{Username="adixon", Password="Yuzge2Eg2Cwqrus", FirstName="Alan", LastName="Dixon", Email="adixon@merch.codes", RoleId=2},
                    new User{Username="sparker", Password="jqrXw4towlCDNMK", FirstName="Steven", LastName="Parker", Email="sparker@merch.codes", RoleId=2},
                    new User{Username="sperez", Password="$Jx8vohtb1aISeh", FirstName="Stephanie", LastName="Perez", Email="sperez@merch.codes", RoleId=3},
                    new User{Username="rbrown", Password="X!Fb9S*(0g5ApXV", FirstName="Ronald", LastName="Brown", Email="rbrown@merch.codes", RoleId=2},
                    new User{Username="sjones", Password="K#OSVDUcVjpm4k3", FirstName="Samantha", LastName="Jones", Email="sjones@merch.codes", RoleId=2},
                    new User{Username="mperez", Password="P^zufyD_mw10ct6", FirstName="Matthew", LastName="Perez", Email="mperez@merch.codes", RoleId=3},
                    new User{Username="projas", Password="vjV7MDki89zodz5", FirstName="Patricia", LastName="Rojas", Email="projas@merch.codes", RoleId=2},
                    new User{Username="mwilliams", Password="_PHTu5Z@@8Wagko", FirstName="Manuel", LastName="Williams", Email="mwilliams@merch.codes", RoleId=1},
                    new User{Username="churst", Password="hNcbQzf4qusmj71", FirstName="Christopher", LastName="Hurst", Email="churst@merch.codes", RoleId=2},
                    new User{Username="nmiller", Password="lkw84x2iwZzZbRV", FirstName="Nicholas", LastName="Miller", Email="nmiller@merch.codes", RoleId=2},
                    new User{Username="lcunningham", Password="Gck-uwrv24gf9pj", FirstName="Laura", LastName="Cunningham", Email="lcunningham@merch.codes", RoleId=2},
                    new User{Username="kmoore", Password="sJWDXDZ!UXRboIu", FirstName="Kimberly", LastName="Moore", Email="kmoore@merch.codes", RoleId=2},
                    new User{Username="rmontgomery", Password="in4pgxank2sv3uq", FirstName="Robert", LastName="Montgomery", Email="rmontgomery@merch.codes", RoleId=2},
                    new User{Username="elopez", Password="kOWG)m7zsmpq99x", FirstName="Elizabeth", LastName="Lopez", Email="elopez@merch.codes", RoleId=3},
                    new User{Username="lmckee", Password="r_bkgx6gjpm8zGY", FirstName="Lisa", LastName="Mckee", Email="lmckee@merch.codes", RoleId=2},
                    new User{Username="jcarter", Password="BO9Gveeflcnbjdr", FirstName="Julie", LastName="Carter", Email="jcarter@merch.codes", RoleId=2},
                    new User{Username="ngomez", Password="hoq7G7sobc-xhkg", FirstName="Nicholas", LastName="Gomez", Email="ngomez@merch.codes", RoleId=2},
                    new User{Username="jboyd", Password="uxelnKb78dwppaJ", FirstName="Jill", LastName="Boyd", Email="jboyd@merch.codes", RoleId=2},
                    new User{Username="kdavidson", Password="ctllo(hvyxrvkhd", FirstName="Kyle", LastName="Davidson", Email="kdavidson@merch.codes", RoleId=2},
                    new User{Username="egriffith", Password="(wsdpjKsiem7sqn", FirstName="Eric", LastName="Griffith", Email="egriffith@merch.codes", RoleId=2},
                    new User{Username="jchen", Password="vzi26mmkkd30Nfu", FirstName="Jack", LastName="Chen", Email="jchen@merch.codes", RoleId=3},
                    new User{Username="jpadilla", Password="k4dP_WAVMAZ3ur3", FirstName="Julie", LastName="Padilla", Email="jpadilla@merch.codes", RoleId=2},
                    new User{Username="jschroeder", Password="eGHeJt!XS$vx5KX", FirstName="Joshua", LastName="Schroeder", Email="jschroeder@merch.codes", RoleId=2},
                    new User{Username="rlawson", Password="NOE_NQyjlyti3en", FirstName="Robert", LastName="Lawson", Email="rlawson@merch.codes", RoleId=3},
                    new User{Username="bruiz", Password="D)(LB!-3nwroltr", FirstName="Betty", LastName="Ruiz", Email="bruiz@merch.codes", RoleId=3},
                    new User{Username="ksantana", Password="tADSEfqn764lFL)", FirstName="Kristin", LastName="Santana", Email="ksantana@merch.codes", RoleId=2},
                    new User{Username="nrice", Password="xfjlrljyv-br4lk", FirstName="Nicole", LastName="Rice", Email="nrice@merch.codes", RoleId=2},
                    new User{Username="tday", Password="AkwYLsob19r0h2X", FirstName="Tammy", LastName="Day", Email="tday@merch.codes", RoleId=2},
                    new User{Username="vcox", Password="b2rnlehoju9mpju", FirstName="Victoria", LastName="Cox", Email="vcox@merch.codes", RoleId=2},
                    new User{Username="jcollins", Password="dVQQP_dMne8nnxr", FirstName="John", LastName="Collins", Email="jcollins@merch.codes", RoleId=2},
                    new User{Username="cbartlett", Password="aw)c6amt5veebqr", FirstName="Christine", LastName="Bartlett", Email="cbartlett@merch.codes", RoleId=2},
                    new User{Username="erodriguez", Password="m36wfKCWSgoEmfm", FirstName="Elizabeth", LastName="Rodriguez", Email="erodriguez@merch.codes", RoleId=2},
                    new User{Username="rkelly", Password="ds)FCHLNOAI7Cil", FirstName="Richard", LastName="Kelly", Email="rkelly@merch.codes", RoleId=3},
                    new User{Username="ablevins", Password="Vekuaahsr9wpXUb", FirstName="Angela", LastName="Blevins", Email="ablevins@merch.codes", RoleId=2},
                    new User{Username="tparker", Password="^p3TSSLbWEFUAPl", FirstName="Tyler", LastName="Parker", Email="tparker@merch.codes", RoleId=2},
                    new User{Username="sdavis", Password="ct4Eyjzygkef8ue", FirstName="Sarah", LastName="Davis", Email="sdavis@merch.codes", RoleId=2},
                    new User{Username="dfranco", Password="I2ICOGXg1jckZVS", FirstName="Dana", LastName="Franco", Email="dfranco@merch.codes", RoleId=2},
                    new User{Username="agonzalez", Password="gWRtF#XWYYXlZWz", FirstName="Ana", LastName="Gonzalez", Email="agonzalez@merch.codes", RoleId=2},
                    new User{Username="mlopez", Password="*$UAvbswYVj8jtF", FirstName="Monica", LastName="Lopez", Email="mlopez@merch.codes", RoleId=3},
                    new User{Username="cgraham", Password="UYSIjscvfp1lbcx", FirstName="Cassandra", LastName="Graham", Email="cgraham@merch.codes", RoleId=2},
                    new User{Username="blawson", Password="owVkektmtg5yq14", FirstName="Bryan", LastName="Lawson", Email="blawson@merch.codes", RoleId=2},
                    new User{Username="smartin", Password="2Cfchdskl7grtwf", FirstName="Scott", LastName="Martin", Email="smartin@merch.codes", RoleId=2},
                    new User{Username="cnelson", Password="gkjx3yzzy9BDIGr", FirstName="Crystal", LastName="Nelson", Email="cnelson@merch.codes", RoleId=3},
                    new User{Username="ahall", Password="psovpdcpwpswgvi", FirstName="Amber", LastName="Hall", Email="ahall@merch.codes", RoleId=2},
                    new User{Username="salexander", Password="wlXGAQLT(j@XHHK", FirstName="Stephen", LastName="Alexander", Email="salexander@merch.codes", RoleId=2},
                    new User{Username="tmadden", Password="_YOJOWyG3mELQr@", FirstName="Tiffany", LastName="Madden", Email="tmadden@merch.codes", RoleId=2},
                    new User{Username="bmckinney", Password="HXxBqXsfj6xlpqs", FirstName="Brooke", LastName="Mckinney", Email="bmckinney@merch.codes", RoleId=2},
                    new User{Username="snoble", Password="akcs0KKKRXPFHqS", FirstName="Samantha", LastName="Noble", Email="snoble@merch.codes", RoleId=2},
                    new User{Username="loneill", Password="%X#BfezcvhZPssp", FirstName="Lindsey", LastName="Oneill", Email="loneill@merch.codes", RoleId=2},
                    new User{Username="rnguyen", Password="LcvdeUd86yzw8y9", FirstName="Robin", LastName="Nguyen", Email="rnguyen@merch.codes", RoleId=1},
                    new User{Username="bscott", Password="!Imfwiju6vwy2)G", FirstName="Barbara", LastName="Scott", Email="bscott@merch.codes", RoleId=2},
                    new User{Username="tshea", Password="eczu6hzwbp^YOTc", FirstName="Timothy", LastName="Shea", Email="tshea@merch.codes", RoleId=2},
                    new User{Username="dconrad", Password="foBiCOKJAPgs0qi", FirstName="David", LastName="Conrad", Email="dconrad@merch.codes", RoleId=3},
                    new User{Username="jballard", Password="8i1eOKUC2zLloo0", FirstName="Jessica", LastName="Ballard", Email="jballard@merch.codes", RoleId=2}
                };

                foreach (User u in users)
                {
                    await usersService.CreateAsync(u);
                }
            }

            if (inventoryService.GetAsync().Result.Count == 0)
            {
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
                    await inventoryService.CreateAsync(i);
                }
            }
        }
    }
}

