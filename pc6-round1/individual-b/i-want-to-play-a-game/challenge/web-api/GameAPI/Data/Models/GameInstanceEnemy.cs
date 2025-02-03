using System.ComponentModel.DataAnnotations;

namespace GameAPI.Data.Models
{
    public class GameInstanceEnemy
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string GameInstanceId { get; set; }
        public string EnemyId { get; set; }
        public short Health { get; set; } = 0;
    }
}
