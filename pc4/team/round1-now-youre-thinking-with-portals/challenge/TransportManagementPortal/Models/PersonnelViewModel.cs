// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using TransportManagementPortal.Data.Models;

namespace TransportManagementPortal.Models
{
    public class PersonnelViewModel
    {
        public List<User> Users { get; set; }
        public string Search { get; set; } 
        public string Message { get; set; }
        public string SqlInectionToken { get; set; }
    }
}
