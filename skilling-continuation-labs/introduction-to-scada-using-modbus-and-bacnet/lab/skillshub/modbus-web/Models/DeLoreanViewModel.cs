/*
Copyright 2025 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

namespace ScadaWeb.Models;

public class DeLoreanViewModel
{
    public ushort ReactorTemp { get; set; }    
    public ushort FuelPercent { get; set; }
    public float Gigawatts { get; set; }
    public ushort CoolantPercent { get; set; }
    public ushort TargetSpeedMPH { get; set; }
    public string SubmitButton { get; set; }
}

