/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using ScadaWeb.Models;
using NModbus;
using NModbus.Device;
using System.Net;
using System.Net.Sockets;
using ScadaWeb.Data;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Runtime.CompilerServices;


namespace ScadaWeb.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly IConfiguration _config;    
    private readonly ScadaDbContext _context;

    public HomeController(ILogger<HomeController> logger, IConfiguration config, ScadaDbContext context)
    {
        _logger = logger;
        _config = config;
        _context = context;
    }

    public IActionResult Index()
    {
        return View();
    }

    public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            var configUser = _config.GetValue<string>("SiteUser");
            var configPassword = _config.GetValue<string>("Password");

            if (username.ToLower() == configUser.ToLower() && password == configPassword)
            {
                // get values from config file
                Response.Cookies.Append("loggedin", "true");
                return RedirectToAction("Index");
            }
            else
            {
                ViewBag.Message = "Invalid email or password.";
                return View();
            }
        }

        public IActionResult Logout()
        {
            Response.Cookies.Delete("loggedin");
            return RedirectToAction("Index");
        }


    public IActionResult Reactors()
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Index");
        }

        ReactorViewModel model = new ReactorViewModel();

        string reactor1Ip = _config.GetValue<string>("Reactor1Ip");
        string reactor1Port = _config.GetValue<string>("Reactor1Port");
        string reactor2Ip = _config.GetValue<string>("Reactor2Ip");
        string reactor2Port = _config.GetValue<string>("Reactor2Port");

        List<ushort> reactorValues = GetReactorValues(reactor1Ip, 0, 1);
        model.Reactor1Temp = reactorValues[0];
        List<ushort> reactorValues2 = GetReactorValues(reactor2Ip, 0, 1);
        model.Reactor2Temp = reactorValues2[0];

        Random random = new Random();
        int randomInt = random.Next(1, 100);
        model.Coolant1Percent = randomInt;
        randomInt = random.Next(1, 100);
        model.Coolant2Percent = randomInt;

        // using (TcpClient client = new TcpClient(reactor1Ip, Convert.ToInt32(reactor1Port)))
        // {
        //     var factory = new ModbusFactory();
        //     IModbusMaster m = factory.CreateMaster(client);

        //     byte sId = 0;
        //     ushort startAddress = 0;
        //     ushort numInputs = 5;
    
        //     ushort[] registers = m.ReadHoldingRegisters(sId, startAddress, numInputs);
        //     string output = "Register Values: ";

        //     for (int i = 0; i < numInputs; i++)
        //     {
        //         output += registers[i] + ", ";
        //     }

        //     model.Reactor1Temp = registers[0];
        // }

        // using (TcpClient client = new TcpClient(reactor2Ip, Convert.ToInt32(reactor2Port)))
        // {
        //     var factory = new ModbusFactory();
        //     IModbusMaster m = factory.CreateMaster(client);

        //     byte sId = 0;
        //     ushort startAddress = 0;
        //     ushort numInputs = 5;
    
        //     ushort[] registers = m.ReadHoldingRegisters(sId, startAddress, numInputs);
        //     string output = "Register Values: ";

        //     for (int i = 0; i < numInputs; i++)
        //     {
        //         output += registers[i] + ", ";
        //     }

        //     model.Reactor2Temp = registers[1];
        // }
        
        return View(model);
    }

    [HttpPost]
    public IActionResult Reactors(ReactorViewModel model)
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Index");
        }

        string reactor1Ip = _config.GetValue<string>("Reactor1Ip");
        string reactor1Port = _config.GetValue<string>("Reactor1Port");
        string reactor2Ip = _config.GetValue<string>("Reactor2Ip");
        string reactor2Port = _config.GetValue<string>("Reactor2Port");

        List<ushort> newReactorValues = null;
        int increment = 0;
        int newReactorValue = 0;
        ushort max = 200;
        ushort min = 160;

        Random random = new Random();
        int randomInt = random.Next(1, 100);
        model.Coolant1Percent = randomInt;
        randomInt = random.Next(1, 100);
        model.Coolant2Percent = randomInt;

        List<ushort> reactorValues = GetReactorValues(reactor1Ip, 0, 1);
        model.Reactor1Temp = reactorValues[0];
        List<ushort> reactorValues2 = GetReactorValues(reactor2Ip, 0, 1);
        model.Reactor2Temp = reactorValues2[0];

        try
        {
            // write flow rates to scada servers here
            switch(model.SubmitButton)
            {
                case "Increase Reactor 1 Temperature":
                    max = 200;
                    newReactorValues = new List<ushort>();
                    increment = 4;
                    newReactorValue = increment + reactorValues[0];
                    if (newReactorValue <= max)
                    {
                        newReactorValues.Add((ushort)newReactorValue);
                        SetReactorValue(reactor1Ip, 0, newReactorValues);
                        model.Reactor1Temp = newReactorValue;
                    }
                    _context.ScadaLogs.Add(new LogEntry { Id = Guid.NewGuid().ToString(), Text = "Reactor 1 temperature increased by tsmith.", CreateDate = DateTime.UtcNow });
                    _context.SaveChanges();
                    break;
                case "Decrease Reactor 1 Temperature":
                    min = 160;   
                    newReactorValues = new List<ushort>();
                    increment = 3;
                    newReactorValue = reactorValues[0] - increment;
                    if (newReactorValue >= min)
                    {
                        newReactorValues.Add((ushort)newReactorValue);
                        SetReactorValue(reactor1Ip, 0, newReactorValues);
                        model.Reactor1Temp = newReactorValue;
                    }
                    _context.ScadaLogs.Add(new LogEntry { Id = Guid.NewGuid().ToString(), Text = "Reactor 1 temperature decreased by tsmith.", CreateDate = DateTime.UtcNow });
                    _context.SaveChanges();
                    break;
                case "Increase Reactor 2 Temperature":
                    max = 250;
                    newReactorValues = new List<ushort>();
                    increment = 7;
                    newReactorValue = increment + reactorValues2[0];
                    if (newReactorValue <= max)
                    {
                        newReactorValues.Add((ushort)newReactorValue);
                        SetReactorValue(reactor2Ip, 0, newReactorValues);
                        model.Reactor2Temp = newReactorValue;
                    }
                    _context.ScadaLogs.Add(new LogEntry { Id = Guid.NewGuid().ToString(), Text = "Reactor 2 temperature increased by tsmith.", CreateDate = DateTime.UtcNow });
                    _context.SaveChanges();
                    break;
                case "Decrease Reactor 2 Temperature":
                    min = 180;
                    newReactorValues = new List<ushort>();
                    increment = 1;
                    newReactorValue = reactorValues2[0] - increment;
                    if (newReactorValue >= min)
                    {
                        newReactorValues.Add((ushort)newReactorValue);
                        SetReactorValue(reactor2Ip, 0, newReactorValues);
                        model.Reactor2Temp = newReactorValue;
                    }
                    _context.ScadaLogs.Add(new LogEntry { Id = Guid.NewGuid().ToString(), Text = "Reactor 2 temperature decreased by tsmith.", CreateDate = DateTime.UtcNow });
                    _context.SaveChanges();
                    break;
            }
        }
        catch (Exception ex)
        {
            ViewBag.Message = "An error occurred while updating the reactors.";
        }

        return View(model);
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

    private void SetReactorValue(string ip, ushort startWriteAddress, List<ushort> reactorValues)
    {
        using (TcpClient client = new TcpClient(ip, 502))
        {
            var factory = new ModbusFactory();
            IModbusMaster m = factory.CreateMaster(client);

            byte sId = 0;
            ushort startAddress = startWriteAddress;
            ushort numInputs = (ushort)reactorValues.Count;
    
            ushort[] registers = m.ReadHoldingRegisters(sId, startAddress, numInputs);
            
            //manipulate register values and write to remote server
            for (int i = 0; i < numInputs; i++)
            {
                registers[i] = (ushort)reactorValues[i];
            }

            // write registers
            m.WriteMultipleRegisters(sId, startAddress, registers);
        }
    }

    public IActionResult Logs()
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Index");
        }

        LogsViewModel model = new LogsViewModel();
        
        return View(model);
    }

    [HttpPost]
    public IActionResult Logs(string query)
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Index");
        }

        LogsViewModel model = new LogsViewModel();

        // var s = "Select tbl_name from sqlite_schema";
        // var fs = FormattableStringFactory.Create(s);
        // var result = _context.Database.SqlQuery<string>(fs).ToList();
        // ViewBag.Result = result;

        var s = "";

        if (string.IsNullOrWhiteSpace(query))
        { 
            s = "select Text from ScadaLogs";
        }
        else
        {
            s = "select Text from ScadaLogs where Text like '%" + query + "%'";
        }

        var fs = FormattableStringFactory.Create(s);
        var result = _context.Database.SqlQuery<string>(fs).ToList();
        ViewBag.Result = result;

        return View(model);   
    }

    public string GetLogIds()
    {
        List<string> ids = new List<string>(){"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"};
        List<string> db_ids = _context.ScadaLogs.Select(l => l.Id).ToList();
        bool containsAny = ids.Any(x => db_ids.Contains(x));
        return containsAny.ToString();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
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
}

