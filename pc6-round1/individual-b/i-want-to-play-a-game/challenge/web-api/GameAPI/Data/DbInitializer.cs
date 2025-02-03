using GameAPI.Data.Models;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using System;
using System.Linq;

namespace GameAPI.Data
{
    public class DbInitializer
    {
        public static void Initialize(GameAPIContext context)
        {
            context.Database.EnsureCreated();

            if (!context.Users.Any())
            {
                var users = new User[]
                {
                    new User{Username="game_server_admin", Email="sleonard@merch.codes", PasswordHash=""},
                    new User{Username="voneill", Email="voneill@merch.codes", PasswordHash="e807f1fcf82d132f9bb018ca6738a19f"},
                    new User{Username="wthomas", Email="wthomas@merch.codes", PasswordHash="7f9a6871b86f40c330132c4fc42cda59"},
                    new User{Username="cgutierrez", Email="cgutierrez@merch.codes", PasswordHash="5eae8782697c15b7a55054c66c96b33a"},
                    new User{Username="tstewart", Email="tstewart@merch.codes", PasswordHash="a5b6e34b25f4722b811d371e957aea29"},
                    new User{Username="mwalker", Email="mwalker@merch.codes", PasswordHash="c26af9f32815ec696fc19aedde845107"},
                    new User{Username="acole", Email="acole@merch.codes", PasswordHash="6238cb036a4229f33c2aac007631f50a"},
                    new User{Username="sbenson", Email="sbenson@merch.codes", PasswordHash="ef9eac94b8de3558aeac904623925ea8"},
                    new User{Username="rlewis", Email="rlewis@merch.codes", PasswordHash="6269a28fc2c053bb09b5c3419fc78f0f"},
                    new User{Username="ckemp", Email="ckemp@merch.codes", PasswordHash="bc6570ddac75155047e5bfa4f8a5afd5"},
                    new User{Username="sbrown", Email="sbrown@merch.codes", PasswordHash="115ee44ef1277a3361073d0561708980"},
                    new User{Username="areynolds", Email="areynolds@merch.codes", PasswordHash="6bad105cd0e2d2e92df6dbac6e44c3b4"},
                    new User{Username="bmason", Email="bmason@merch.codes", PasswordHash="e07ba32ec356215f04d973baae0a9bff"},
                    new User{Username="nburnett", Email="nburnett@merch.codes", PasswordHash="be96fd4b1e6c68df5e1b1212e4c2b655"},
                    new User{Username="javila", Email="javila@merch.codes", PasswordHash="b1bd31204bba020009882d981dd5a3c6"},
                    new User{Username="elynn", Email="elynn@merch.codes", PasswordHash="a995eb8035972d669d4f226c080693fe"},
                    new User{Username="etapia", Email="etapia@merch.codes", PasswordHash="c20740d5f2f68fe559bb2658866cc45c"},
                    new User{Username="jreese", Email="jreese@merch.codes", PasswordHash="780dbd9b82684085ceb558ca546b8326"},
                    new User{Username="jchang", Email="jchang@merch.codes", PasswordHash="4660f3f47992f9643162f2e1bddc826b"},
                    new User{Username="twoods", Email="twoods@merch.codes", PasswordHash="ccf896f2b629fc70d05f2a4e818f51e7"},
                    new User{Username="acarter", Email="acarter@merch.codes", PasswordHash="92dfe533f1c8e69801a10316d96c87ae"},
                    new User{Username="sdavis", Email="sdavis@merch.codes", PasswordHash="efe0a6472911cd1de885b9a2fdf3a329"},
                    new User{Username="shicks", Email="shicks@merch.codes", PasswordHash="461f19424dcb87b2211ed2f4ba373ce4"},
                    new User{Username="oduran", Email="oduran@merch.codes", PasswordHash="41b0100627852f899eda198f76796cbc"},
                    new User{Username="eterrell", Email="eterrell@merch.codes", PasswordHash="8ebef40c6e9c8f74336e1eecc79539ea"}
                };

                foreach (User u in users)
                {
                    context.Users.Add(u);
                }
            }

            if (!context.Items.Any())
            {
                var items = new Item[]
                {
                    new Item{Name="Clothes"},
                    new Item{Name="Wooden Sword"},
                    new Item{Name="Steel Sword"},
                    new Item{Name="Magic Sword"},
                    new Item{Name="Leather Armor"},
                    new Item{Name="Metal Armor"},
                    new Item{Name="Magic Armor"},
                    new Item{Name="Meat"},
                    new Item{Name="Healing Potion"},
                    new Item{Name="Spell Book"},
                    new Item{Name="Torch"},
                    new Item{Name="Magic Wand"},
                    new Item{Name="Boomerang"},
                    new Item{Name="Key"}
                };

                foreach (Item i in items)
                {
                    context.Items.Add(i);
                }
            }

            if (!context.UserItems.Any())
            {
                var userItems = new UserItem[]
                {
                    //new UserItem{}
                };

                foreach (UserItem ui in userItems)
                {
                    context.UserItems.Add(ui);
                }
            }

            if (!context.Enemies.Any())
            {
                var enemies = new Enemy[]
                {
                    new Enemy{Name = "Slime", Health = 100},
                    new Enemy{Name = "Werewolf", Health = 500},
                    new Enemy{Name = "Dragon", Health = 1000},
                    new Enemy{Name = "Python", Health = 1200},
                    new Enemy{Name = "Troll", Health = 1800},
                    new Enemy{Name = "Red Guard", Health = 2000},
                    new Enemy{Name = "Silver Guard", Health = 2500},
                    new Enemy{Name = "Centaur", Health = 2800},
                    new Enemy{Name = "Iron Snake", Health = 3000},
                    new Enemy{Name = "Magic Falcon", Health = 3500},
                    new Enemy{Name = "Wizard", Health = 4000},
                    new Enemy{Name = "Invisible Wizard", Health = 4500},
                    new Enemy{Name = "Flame Dragon", Health = 5000},
                    new Enemy{Name = "Silver Dragon", Health = 20000},
                };

                foreach (Enemy e in enemies)
                {
                    context.Enemies.Add(e);
                }
            }

            context.SaveChanges();
        }
    }
}
