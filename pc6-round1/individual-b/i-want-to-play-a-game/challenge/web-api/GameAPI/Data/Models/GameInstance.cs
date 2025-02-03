using System.ComponentModel.DataAnnotations;

namespace GameAPI.Data.Models
{
    public class GameInstance
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string UserId { get; set; }
        public string GameState { get; set; } = "Running";
        public string? Message { get; set; }
        public List<GameInstanceEnemy> GameInstanceEnemies = new List<GameInstanceEnemy>();
    }
}
