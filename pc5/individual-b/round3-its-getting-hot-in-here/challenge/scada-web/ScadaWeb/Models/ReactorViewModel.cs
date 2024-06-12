/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

namespace ScadaWeb.Models;

public class ReactorViewModel
{
    public int Reactor1Temp { get; set; }    
    public int Reactor2Temp { get; set; }
    public int Coolant1Percent { get; set; }
    public int Coolant2Percent { get; set; } 
    public string SubmitButton { get; set; }
}

