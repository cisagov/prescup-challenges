using System.ComponentModel.DataAnnotations;

namespace GameAPI.Data.Models
{
    public class Item
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; }
        public string? Description { get; set; }
    }
}
