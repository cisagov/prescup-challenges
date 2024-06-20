/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

namespace ScadaWeb.Models;

public class FireSuppressionViewModel
{
    // Modbus holding register addresses for room temps
    public int PilotingRegisterRoomTempAddress { get; set; } = 0;
    public int EngineeringRegisterRoomTempAddress { get; set; } = 0;
    public int DCRegisterRoomTempAddress { get; set; } = 0;
    public int CommsRegisterRoomTempAddress { get; set; } = 0;
    public int PShuttleRegisterRoomTempAddress { get; set; } = 0;
    public int OpsRegisterRoomTempAddress { get; set; } = 0;
    public int SShuttleRegisterRoomTempAddress { get; set; } = 0;
          
    // Doors:
    public bool Door1Coil { get; set; } =  false;
    public bool Door2Coil { get; set; } =  false;
    public bool Door3Coil { get; set; } =  false;
    public bool Door4Coil { get; set; } =  false;
    public bool Door5Coil { get; set; } =  false;
    public bool Door6Coil { get; set; } =  false;

    // Fire Suppression:
    public bool PilotingFireSuppressionDoor1Coil { get; set; } =  false;
    public bool EngineeringFireSuppressionDoor2Coil { get; set; } = false;
    public bool DCFireSuppressionDoor3Coil { get; set; } = false;
    public bool CommsFireSuppressionDoor4Coil { get; set; } = false;
    public bool OpsFireSuppressionDoor5Coil { get; set; } = false;

    // Smoke Sensors:
    public bool PilotingSmokeSensor1Coil { get; set; } = false;
    public bool EngineeringSmokeSensor2Coil { get; set; } = false;
    public bool DCSmokeSensor3Coil { get; set; } = false;
    public bool CommsSmokeSensor4Coil { get; set; } = false;
    public bool OpsSmokeSensor5Coil { get; set; } = false;
    public bool PShuttleSmokeSensor6Coil { get; set; } = false;
    public bool SShuttleSmokeSensor7Coil { get; set; } = false;
}

