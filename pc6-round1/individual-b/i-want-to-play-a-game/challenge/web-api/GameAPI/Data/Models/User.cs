using System.ComponentModel.DataAnnotations;

namespace GameAPI.Data.Models
{
    public class User
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Username { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public int RoleId { get; set; } = 1;
        public int CurrentXLocation { get; set; } = 500;
        public int CurrentYLocation { get; set; } = 500;
        public string AuthToken { get; set; } = Guid.NewGuid().ToString().Replace("-", "") + Guid.NewGuid().ToString().Replace("-", "");
        public int Level { get; set; } = 0;
        public int Health { get; set; } = 100;
    }
}
