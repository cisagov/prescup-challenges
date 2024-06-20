/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using ManagementPortal.Data.Models;

namespace ManagementPortal.Models
{
    public class LogsViewModel
    {
        public string LogData { get; set;}
        public string LogEndpoint { get; set;}
        public string Message { get; set; }
    }
}
