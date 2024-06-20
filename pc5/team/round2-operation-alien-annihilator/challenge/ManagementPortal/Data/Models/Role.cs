/*
Copyright 2024 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
*/

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace ManagementPortal.Data.Models
{
    public class Role
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string ObjectId { get; set; }
        public int Id { get; set; }
        public string RoleName { get; set; }
    }
}

