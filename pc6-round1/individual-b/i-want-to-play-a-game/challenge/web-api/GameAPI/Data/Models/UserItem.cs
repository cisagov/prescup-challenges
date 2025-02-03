using System.ComponentModel.DataAnnotations;

namespace GameAPI.Data.Models
{
    public class UserItem
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string UserId { get; set; }
        public string ItemId { get; set; }
        public int Quantity { get; set; }
    }
}
