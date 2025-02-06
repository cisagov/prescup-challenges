using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using PoolVendorWeb.Models;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;


namespace PoolVendorWeb.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly IConfiguration _config;

    public HomeController(ILogger<HomeController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult About()
    {
        return View();
    }

    public IActionResult Documentation()
    {
        DocumentationViewModel model = new DocumentationViewModel();
        return View(model);
    }

    [HttpPost]
    public IActionResult Documentation(DocumentationViewModel model)
    {
        if (model != null)
        {
            if (!string.IsNullOrWhiteSpace(model.SearchTerm) &&
                model.SearchTerm.Contains("38119"))
            {
                model.Message = "You searched for: " + model.SearchTerm + ". There is 1 result.";
                List<string> searchResults = new List<string>();
                searchResults.Add("<a href='/files/38119.txt' target='_blank'>Model 38119 Thermo Control Quick Start Guide</a>");
                model.SearchResults = searchResults;
            }
            else
            {
                model.Message = "You searched for: " + model.SearchTerm + ". There were no results returned.";
            }

        }
        else
        {
            model = new DocumentationViewModel();
            model.Message = "No results for this search.";
        }

        return View(model);
    }


    // public IActionResult Login()
    // {
    //     return View();
    // }

    // [HttpPost]
    // public IActionResult Login(string username, string password)
    // {
    //     var configUser = _config.GetValue<string>("SiteUser");
    //     var configPassword = _config.GetValue<string>("Password");

    //     if (username.ToLower() == configUser.ToLower() && password == configPassword)
    //     {
    //         // get values from config file
    //         Response.Cookies.Append("loggedin", "true");
    //         return RedirectToAction("Index");
    //     }
    //     else
    //     {
    //         ViewBag.Message = "Invalid username or password.";
    //         return View();
    //     }
    // }

    // public IActionResult Logout()
    // {
    //     Response.Cookies.Delete("loggedin");
    //     return RedirectToAction("Index");
    // }

    // public IActionResult SystemStatus()
    // {
    //     // if (!IsUserLoggedIn())
    //     // {
    //     //     return RedirectToAction("Index");
    //     // }

    //     /*
    //     # Modbus server address and port
    //     server_address = "10.3.3.200"
    //     server_port = 502
    //     */

    //     //FireSuppressionViewModel model = new FireSuppressionViewModel();

    //     // string modbusServer1Ip = _config.GetValue<string>("ModbusServer1Ip");
    //     // string modbusServer1Port = _config.GetValue<string>("ModbusServer1Port");

    //     // List<ushort> fireSuppressionRegisterValues = GetModbusRegisterValues(modbusServer1Ip, 0, 7);

    //     // // Modbus holding register addresses for room temps
    //     // model.PilotingRegisterRoomTempAddress = fireSuppressionRegisterValues[0];
    //     // model.EngineeringRegisterRoomTempAddress = fireSuppressionRegisterValues[1];
    //     // model.DCRegisterRoomTempAddress = fireSuppressionRegisterValues[2];
    //     // model.CommsRegisterRoomTempAddress = fireSuppressionRegisterValues[3];
    //     // model.PShuttleRegisterRoomTempAddress = fireSuppressionRegisterValues[4];
    //     // model.OpsRegisterRoomTempAddress = fireSuppressionRegisterValues[5];
    //     // model.SShuttleRegisterRoomTempAddress = fireSuppressionRegisterValues[6];

    //     // List<bool> fireSuppressionCoilValues = GetModbusCoilValues(modbusServer1Ip, 1, 18);

    //     // // Doors:
    //     // model.Door1Coil = fireSuppressionCoilValues[0];
    //     // model.Door2Coil = fireSuppressionCoilValues[1];
    //     // model.Door3Coil = fireSuppressionCoilValues[2];
    //     // model.Door4Coil = fireSuppressionCoilValues[3];
    //     // model.Door5Coil = fireSuppressionCoilValues[4];
    //     // model.Door6Coil = fireSuppressionCoilValues[5];

    //     // // Fire Suppression:
    //     // model.PilotingFireSuppressionDoor1Coil = fireSuppressionCoilValues[6];
    //     // model.EngineeringFireSuppressionDoor2Coil = fireSuppressionCoilValues[7];
    //     // model.DCFireSuppressionDoor3Coil = fireSuppressionCoilValues[8];
    //     // model.CommsFireSuppressionDoor4Coil = fireSuppressionCoilValues[9];
    //     // model.OpsFireSuppressionDoor5Coil = fireSuppressionCoilValues[10];

    //     // // Smoke Sensors:
    //     // model.PilotingSmokeSensor1Coil = fireSuppressionCoilValues[11];
    //     // model.EngineeringSmokeSensor2Coil = fireSuppressionCoilValues[12];
    //     // model.DCSmokeSensor3Coil = fireSuppressionCoilValues[13];
    //     // model.CommsSmokeSensor4Coil = fireSuppressionCoilValues[14];
    //     // model.PShuttleSmokeSensor6Coil = fireSuppressionCoilValues[15];
    //     // model.OpsSmokeSensor5Coil = fireSuppressionCoilValues[16];
    //     // model.SShuttleSmokeSensor7Coil = fireSuppressionCoilValues[17];

    //     return View(model);
    // }

    // private List<ushort> GetModbusRegisterValues(string ip, ushort startReadAddress, ushort numberOfValues)
    // {
    //     List<ushort> values = new List<ushort>();

    //     using (TcpClient client = new TcpClient(ip, 502))
    //     {
    //         var factory = new ModbusFactory();
    //         IModbusMaster m = factory.CreateMaster(client);
    //         byte sId = 0;
    //         ushort[] registers = m.ReadHoldingRegisters(sId, startReadAddress, numberOfValues);
    //         values = registers.ToList();
    //     }

    //     return values;
    // }

    // private List<bool> GetModbusCoilValues(string ip, ushort startReadAddress, ushort numberOfValues)
    // {
    //     List<bool> values = new List<bool>();

    //     using (TcpClient client = new TcpClient(ip, 502))
    //     {
    //         var factory = new ModbusFactory();
    //         IModbusMaster m = factory.CreateMaster(client);
    //         byte sId = 0;
    //         bool[] coils = m.ReadCoils(sId, startReadAddress, numberOfValues);
    //         values = coils.ToList();
    //     }

    //     return values;
    // }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }

    // private bool IsUserLoggedIn()
    // {
    //     if (Request.Cookies["loggedin"] == null || Request.Cookies["loggedin"] != "true")
    //     {
    //         return false;
    //     }
    //     else
    //     {
    //         return true;
    //     }
    // }
}
