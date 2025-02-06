using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using PoolWeb.Models;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using NModbus;
using NModbus.Device;


namespace PoolWeb.Controllers;

public class AdminController : Controller
{
    private readonly ILogger<AdminController> _logger;
    private readonly IConfiguration _config;

    public AdminController(ILogger<AdminController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
    }

    public IActionResult Index()
    {
        IndexViewModel model = new IndexViewModel();

        if (IsUserLoggedIn())
        {
            using (var sr = new StreamReader("token1.txt"))
            {
                model.Token1 = sr.ReadToEnd();
            }
        }

        return View(model);
    }

    public IActionResult AdminMain()
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Home", "Index");
        }

        AdminViewModel model = new AdminViewModel();

        if (Request.Cookies["SetMainPoolTemperature"] != null && !string.IsNullOrWhiteSpace(Request.Cookies["SetMainPoolTemperature"]))
        {
            model.MainPoolTemperature = Convert.ToInt32(Request.Cookies["SetMainPoolTemperature"]);
            model.SetMainPoolTemperature = Convert.ToInt32(Request.Cookies["SetMainPoolTemperature"]);
        }
        else
        {
            model.MainPoolTemperature = 82;
        }

        return View(model);
    }

    [HttpPost]
    public IActionResult AdminMain(AdminViewModel model)
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Home", "Index");
        }

        if (model == null)
        {
            model = new AdminViewModel();
        }

        if (string.IsNullOrWhiteSpace(model.AutomatedPoolManagementUsername) || string.IsNullOrWhiteSpace(model.AutomatedPoolManagementPassword))
        {
            model.Message = "Authentication Error";
            return View(model);
        }
        else
        {
            if (model.AutomatedPoolManagementUsername.ToLower() != "apmadmin" || model.AutomatedPoolManagementPassword != "38119thermo")
            {
                model.Message = "Authentication Error";
                return View(model);
            }
        }

        if (model.SetMainPoolTemperature >= 110)
        {
            string token2 = string.Empty;

            if (model.AutomatedPoolManagementUsername.ToLower() == "apmadmin" || model.AutomatedPoolManagementPassword == "38119thermo")
            {

                using (var sr = new StreamReader("token2.txt"))
                {
                    token2 = sr.ReadToEnd();
                    model.Token2 = token2;
                    model.Message = "You have been awarded with Token 2: " + token2;
                }

                model.MainPoolTemperature = model.SetMainPoolTemperature;
                Response.Cookies.Append("Token2", token2);
                Response.Cookies.Append("SetMainPoolTemperature", model.SetMainPoolTemperature.ToString());
            }
        }

        return View(model);
    }

    public IActionResult PoolConditions()
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Home", "Index");
        }

        PoolConditionsViewModel model = new PoolConditionsViewModel();

        string poolScadaServerIp = _config.GetValue<string>("PoolScadaServerIp");

        List<ushort> poolValues = GetReactorValues(poolScadaServerIp, 0, 3);
        // foreach(var v in poolValues)
        // {
        //     Console.WriteLine(v);
        //     model.Message += v.ToString() + " -- ";
        // }

        model.pH = poolValues[0];
        model.FreeAvailableChlorine = poolValues[1];
        model.TotalAlkalinity = poolValues[2];

        if (model.pH == 6 && model.FreeAvailableChlorine == 4 && model.TotalAlkalinity == 70)
        {
            using (var sr = new StreamReader("token4.txt"))
            {
                model.Token4 = sr.ReadToEnd();
            }
        }

        return View(model);
    }

    private bool IsUserLoggedIn()
    {
        if (Request.Cookies["loggedin"] == null || Request.Cookies["loggedin"] != "true")
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    private List<ushort> GetReactorValues(string ip, ushort startReadAddress, ushort numberOfValues)
    {
        List<ushort> reactorValues = new List<ushort>();

        using (TcpClient client = new TcpClient(ip, 502))
        {
            var factory = new ModbusFactory();
            IModbusMaster m = factory.CreateMaster(client);

            byte sId = 0;
            ushort startAddress = startReadAddress;
            ushort numInputs = numberOfValues;

            ushort[] registers = m.ReadHoldingRegisters(sId, startAddress, numInputs);
            reactorValues = registers.ToList();

            return reactorValues;
        }
    }
}
