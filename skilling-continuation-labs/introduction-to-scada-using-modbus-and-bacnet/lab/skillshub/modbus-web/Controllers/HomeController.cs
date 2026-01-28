/*
Copyright 2025 Carnegie Mellon University.
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
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;


namespace ScadaWeb.Controllers;

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
            ViewBag.Message = "Invalid username or password.";
            return View();
        }
    }

    public IActionResult Logout()
    {
        Response.Cookies.Delete("loggedin");
        return RedirectToAction("Index");
    }

    public IActionResult HangarStatus()
    {
        var hangarStatus = string.Empty;

        try
        {
            // Open the text file using a stream reader.
            using (var sr = new StreamReader("bacnet_status.json"))
            {
                // Read the stream as a string, and write the string to the console.
                hangarStatus = sr.ReadToEnd();
            }

            ViewBag.HangarStatus = hangarStatus;

            JsonNode? jsonNode = JsonNode.Parse(hangarStatus);

            if (jsonNode is JsonObject jsonObject)
            {
                if (jsonObject["GarageDoor"] is JsonObject garageDoorObject)
                {
                    ViewBag.DoorState = garageDoorObject["DoorState"]?.GetValue<string>();
                }

                if (jsonObject["Thermostat"] is JsonObject thermostatObject)
                {
                    ViewBag.RoomTemp = thermostatObject["RoomTemp"]?.GetValue<float>();
                    ViewBag.SetTemp = thermostatObject["SetTemp"]?.GetValue<float>();
                    ViewBag.SystemMode = thermostatObject["SystemMode"]?.GetValue<float>();
                }

                if (jsonObject["AlarmPanel"] is JsonObject alarmPanelObject)
                {
                    ViewBag.AlarmState = alarmPanelObject["AlarmState"]?.GetValue<string>();
                    ViewBag.DisarmCode = alarmPanelObject["DisarmCode"]?.GetValue<float>();
                }
            }

            if(ViewBag.DoorState == "active" && ViewBag.AlarmState == "inactive")
            {
                using (var sr = new StreamReader("alarmoff.txt"))
                {
                    var bacnetToken = string.Empty;
                    bacnetToken = sr.ReadToEnd();
                    ViewBag.BACnetToken = bacnetToken;
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }

        return View();
    }

    private List<ushort> GetModbusRegisterValues(string ip, string port, ushort startReadAddress, ushort numberOfValues)
    {
        List<ushort> values = new List<ushort>();

        using (TcpClient client = new TcpClient(ip, Convert.ToUInt16(port)))
        {
            var factory = new ModbusFactory();
            IModbusMaster m = factory.CreateMaster(client);
            byte sId = 0;    
            ushort[] registers = m.ReadHoldingRegisters(sId, startReadAddress, numberOfValues);
            values = registers.ToList();
        }

        return values;
    }

    private List<bool> GetModbusCoilValues(string ip, string port, ushort startReadAddress, ushort numberOfValues)
    {
        List<bool> values = new List<bool>();

        using (TcpClient client = new TcpClient(ip, Convert.ToUInt16(port)))
        {
            var factory = new ModbusFactory();
            IModbusMaster m = factory.CreateMaster(client);
            byte sId = 0;
            bool[] coils = m.ReadCoils(sId, startReadAddress, numberOfValues);
            values = coils.ToList();
        }

        return values;
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

    public IActionResult DeLorean()
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Index");
        }

        DeLoreanViewModel model = new DeLoreanViewModel();
        string deloreanIp = _config.GetValue<string>("DeLoreanServerIp");
        string deloreanPort = _config.GetValue<string>("DeLoreanServerPort");

        List<ushort> deloreanValues = GetReactorValues(deloreanIp, deloreanPort, 0, 4);
        model.CoolantPercent = deloreanValues[0];
        model.FuelPercent = deloreanValues[1];
        model.TargetSpeedMPH = deloreanValues[2];
        model.ReactorTemp = deloreanValues[3];

        if (model.ReactorTemp > 900 && model.ReactorTemp <= 950)
        {
            model.Gigawatts = 1.21F;
        }
        else if (model.ReactorTemp > 950)
        {
            model.Gigawatts = 1.41F;
        }
        else
        {
            model.Gigawatts = .95F;
        }

        if ((model.ReactorTemp > 900 && model.ReactorTemp <= 950) && model.TargetSpeedMPH == 88 && model.FuelPercent >= 80)
        {
            using (var sr = new StreamReader("88mph.txt"))
            {
                var modbusToken = string.Empty;
                modbusToken = sr.ReadToEnd();
                ViewBag.ModbusToken = modbusToken;
            }
        }
        
        return View(model);
    }

    [HttpPost]
    public IActionResult DeLorean(DeLoreanViewModel model)
    {
        if (!IsUserLoggedIn())
        {
            return RedirectToAction("Index");
        }

        string deloreanIp = _config.GetValue<string>("DeLoreanServerIp");
        string deloreanPort = _config.GetValue<string>("DeLoreanServerPort");

        ushort increment = 5;
        ushort max = 1000;
        ushort min = 750;

        List<ushort> deloreanValues = GetReactorValues(deloreanIp, deloreanPort, 0, 4);
        model.CoolantPercent = deloreanValues[0];
        model.FuelPercent = deloreanValues[1];
        model.TargetSpeedMPH = deloreanValues[2];
        model.ReactorTemp = deloreanValues[3];

        try
        {
            // write flow rates to scada servers here
            switch(model.SubmitButton)
            {
                case "Increase Reactor Temperature":
                    if ((model.ReactorTemp + increment) <= max)
                    {
                        model.ReactorTemp = (ushort)(model.ReactorTemp + increment);
                        deloreanValues[3] = model.ReactorTemp;
                        SetReactorValue(deloreanIp, deloreanPort, 0, deloreanValues);
                    }
                    break;
                case "Decrease Reactor Temperature":
                    if ((model.ReactorTemp - increment) >= min)
                    {
                        model.ReactorTemp = (ushort)(model.ReactorTemp - increment);
                        deloreanValues[3] = model.ReactorTemp;
                        SetReactorValue(deloreanIp, deloreanPort, 0, deloreanValues);
                    }
                    break;
            }
        }
        catch (Exception ex)
        {
            ViewBag.Message = "An error occurred while updating the reactors.";
        }

        if (model.ReactorTemp > 900 && model.ReactorTemp <= 950)
        {
            model.Gigawatts = 1.21F;
        }
        else if (model.ReactorTemp > 950)
        {
            model.Gigawatts = 1.41F;
        }
        else
        {
            model.Gigawatts = .95F;
        }

        if ((model.ReactorTemp > 900 && model.ReactorTemp <= 950) && model.TargetSpeedMPH == 88 && model.FuelPercent >= 80)
        {
            using (var sr = new StreamReader("88mph.txt"))
            {
                var modbusToken = string.Empty;
                modbusToken = sr.ReadToEnd();
                ViewBag.ModbusToken = modbusToken;
            }
        }

        return View(model);
    }

    private List<ushort> GetReactorValues(string ip, string port, ushort startReadAddress, ushort numberOfValues)
    {
        List<ushort> reactorValues = new List<ushort>();

        using (TcpClient client = new TcpClient(ip, Convert.ToUInt16(port)))
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

    private void SetReactorValue(string ip, string port, ushort startWriteAddress, List<ushort> reactorValues)
    {
        using (TcpClient client = new TcpClient(ip, Convert.ToUInt16(port)))
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
}

