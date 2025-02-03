using GameAPI.Data.Models;
using Microsoft.EntityFrameworkCore;

namespace GameAPI.Data
{
    public class GameAPIContext : DbContext
    {
        public GameAPIContext(DbContextOptions<GameAPIContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Enemy> Enemies { get; set; }
        public DbSet<Item> Items { get; set; }
        public DbSet<UserItem> UserItems { get; set; }
        public DbSet<GameInstance> GameInstances { get; set; }
        public DbSet<GameInstanceEnemy> GameInstanceEnemies { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("Users");
            modelBuilder.Entity<Enemy>().ToTable("Enemies");
            modelBuilder.Entity<Item>().ToTable("Items");
            modelBuilder.Entity<UserItem>().ToTable("UserItems");
            modelBuilder.Entity<GameInstance>().ToTable("GameInstances");
            modelBuilder.Entity<GameInstanceEnemy>().ToTable("GameInstanceEnemies");
        }
    }
}
