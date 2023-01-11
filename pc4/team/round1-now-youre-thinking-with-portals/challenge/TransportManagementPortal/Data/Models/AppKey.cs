// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using System.ComponentModel.DataAnnotations;

namespace TransportManagementPortal.Data.Models
{
    public class AppKey
    {
        [Key]
        public string KeyValue { get; set; } = Guid.NewGuid().ToString();
        public string KeyType { get; set; }
        public bool IsAvailable { get; set; }
    }
}
