// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using TransportManagementPortal.Data.Models;

namespace TransportManagementPortal.Models
{
    public class TransportSystemStatusViewModel
    {
        public List<TransportSystem> TransportSystems { get; set; }
        public string ManagementAPIToken { get; set; }
    }
}
