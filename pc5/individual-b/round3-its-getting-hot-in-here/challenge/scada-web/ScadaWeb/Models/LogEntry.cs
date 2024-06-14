/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using System.ComponentModel.DataAnnotations;

namespace ScadaWeb.Models;

public class LogEntry
{
    public string Id { get; set; }
    public string Text { get; set; }
    [DataType(DataType.Date)]
    public DateTime CreateDate { get; set; }
}

