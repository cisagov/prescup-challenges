using GameAPI.Data;
using GameAPI.Data.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace GameAPI.Controllers
{
    [ApiController]
    [Route("api/game")]
    public class GameController : BaseController
    {
        private readonly ILogger<GameController> _logger;
        private readonly IConfiguration _configuration;
        private readonly GameAPIContext _context;
        private readonly GameAPIContext _gameAPIContext;

        public GameController(ILogger<GameController> logger, IConfiguration configuration, GameAPIContext context, GameAPIContext gameAPIContext
        ) : base(configuration, gameAPIContext)
        {
            _logger = logger;
            _configuration = configuration;
            _context = context;
            _gameAPIContext = gameAPIContext;
        }

        [HttpGet]
        [Route("ListEnemies")]
        public JsonResult ListEnemies()
        {
            if (!IsUserAuthenticated())
            {
                return Json("Missing or invalid authentication token.");
            }

            List<Enemy> enemies = _gameAPIContext.Enemies.ToList();

            return Json(enemies);
        }

        [HttpGet]
        [Route("ListUserIdsAndNames")]
        public JsonResult ListUserIdsAndNames()
        {
            if (!IsUserAuthenticated())
            {
                return Json("Missing or invalid authentication token.");
            }

            var users = _gameAPIContext.Users.Select(u => new { u.Id, u.Username }).ToList();

            return Json(users);
        }

        [HttpPost]
        [Route("MoveTo")]
        public JsonResult MoveToLocation(string user_id, int current_x, int current_y, int new_x, int new_y)
        {
            if (!IsUserAuthenticated())
            {
                return Json("Missing or invalid authentication token.");
            }

            return Json("Not yet implemented");
        }

        [HttpPost]
        [Route("Login")]
        public JsonResult Login(string username, string password)
        {
            // returns a token that must be passed with other requests
            if (!IsUserAuthenticated())
            {
                password = CreateMD5Hash(password.Trim());
                Console.WriteLine(password);

                GameAPI.Data.Models.User user = _gameAPIContext.Users.Where(u => u.Username.ToLower() == username.Trim().ToLower()
                    && password == u.PasswordHash).FirstOrDefault();

                if (user == null)
                {
                    return Json("Invalid username or password.");
                }
                else
                {
                    // if a game instance for this user does not exist, create it
                    CreateGameInstance(user.Id);
                    return Json("UserAuthToken: " + user.AuthToken);
                }
            }
            else
            {
                string userAuthToken = Request.Headers["UserAuthToken"].FirstOrDefault();
                User user = _gameAPIContext.Users.Where(u => u.AuthToken == userAuthToken).FirstOrDefault();

                if (user == null)
                {
                    return Json("Invalid authentication token.");
                }

                CreateGameInstance(user.Id);

                return Json("UserAuthToken: " + Request.Headers["UserAuthToken"].FirstOrDefault().ToString());
            }
        }

        [HttpPost]
        [Route("Attack")]
        public JsonResult Attack(string user_id, string enemy_id, short damage_amt)
        {
            if (!IsUserAuthenticated())
            {
                return Json("Missing or invalid authentication token.");
            }

            // validate user
            string userAuthToken = Request.Headers["UserAuthToken"].FirstOrDefault();
            User user = _gameAPIContext.Users.Where(u => u.AuthToken == userAuthToken).FirstOrDefault();

            if (user == null)
            {
                return Json("Invalid user.");
            }
            else if (user.Id != user_id)
            {
                return Json("Invalid user_id. You do not have permission to access this user_id");
            }

            // validate target
            Enemy enemy = _gameAPIContext.Enemies.Where(e => e.Id == enemy_id).FirstOrDefault();

            if (enemy == null)
            {
                return Json("Invalid enemy_id");
            }

            // apply damage and implement buggy logic
            if (damage_amt > 100)
            {
                return Json("The damage amount for an attack can not be greater than 100.");
            }

            GameInstance gameInstance = _gameAPIContext.GameInstances.Where(gi => gi.UserId == user.Id).FirstOrDefault();
            GameInstanceEnemy boss = _gameAPIContext.GameInstanceEnemies.Where(gie => gie.EnemyId == enemy.Id && gie.GameInstanceId == gameInstance.Id).FirstOrDefault();

            if (gameInstance.GameState == "GameOver")
            {
                string question3token = string.Empty;

                using (var sr = new StreamReader("boss_token.txt"))
                {
                    question3token = sr.ReadToEnd();
                }

                return Json("You defeated the final boss. Here is your token for question #3: " + question3token);
            }

            if (boss != null)
            {
                if (boss.Health < 0 && gameInstance.GameState != "GameOver")
                {
                    boss.Health = 10000;
                    _gameAPIContext.GameInstanceEnemies.Update(boss);
                    _gameAPIContext.SaveChanges();

                    return Json("Boss health: " + boss.Health.ToString());
                }

                if ((boss.Health - damage_amt) < 0 && gameInstance.GameState == "Running")
                {
                    string question3token = string.Empty;

                    using (var sr = new StreamReader("boss_token.txt"))
                    {
                        question3token = sr.ReadToEnd();
                    }

                    gameInstance.GameState = "GameOver";
                    _gameAPIContext.GameInstances.Update(gameInstance);
                    _gameAPIContext.SaveChanges();

                    return Json("You defeated the final boss. Here is your token for question #3: " + question3token);
                }
                else
                {
                    boss.Health = (short)(boss.Health - damage_amt);
                    _gameAPIContext.GameInstanceEnemies.Update(boss);
                    _gameAPIContext.SaveChanges();
                }
            }
            else
            {
                return Json("Error retrieving final boss state.");
            }

            return Json("Boss health: " + boss.Health.ToString());
        }

        [HttpPost]
        [Route("Heal")]
        public JsonResult Heal(string user_id, int life_amt)
        {
            if (!IsUserAuthenticated())
            {
                return Json("Missing or invalid authentication token.");
            }

            return Json("Not yet implemented");
        }

        [HttpPost]
        [Route("GetItem")]
        public JsonResult GetItem(string user_id, string item_id)
        {
            if (!IsUserAuthenticated())
            {
                return Json("Missing or invalid authentication token.");
            }

            return Json("Not yet implemented");
        }

        [HttpPost]
        [Route("ReadFileContents")]
        public JsonResult ReadFileContents(string user_id, string filePath)
        {
            if (!filePath.ToLower().EndsWith(".txt"))
            {
                return Json("Invalid file extension.");
            }

            User user = _gameAPIContext.Users.Where(u => u.Id == user_id).FirstOrDefault();

            if (user == null)
            {
                return Json("Invalid user.");
            }
            else if (user.Username != "game_server_admin")
            {
                return Json("You must be an admin to use this feature.");
            }

            string fileContents = "";

            try
            {
                using (var sr = new StreamReader(Environment.CurrentDirectory + "/" + filePath))
                {
                    fileContents = sr.ReadToEnd();
                }
            }
            catch (Exception exc)
            {
                fileContents = exc.Message;
            }

            return Json(fileContents);
        }

        [HttpPost]
        [Route("UseItem")]
        public JsonResult UseItem(string user_id, string item_id, string target_id)
        {
            if (!IsUserAuthenticated())
            {
                return Json("Missing or invalid authentication token.");
            }

            return Json("Not yet implemented");
        }

        private void ResetGameInstance(string userId)
        {
            GameInstance gameInstance = _gameAPIContext.GameInstances.Where(gi => gi.UserId == userId).FirstOrDefault();
            List<GameInstanceEnemy> gameInstanceEnemies = _gameAPIContext.GameInstanceEnemies.Where(gie => gie.GameInstanceId == gameInstance.Id).ToList();
            _gameAPIContext.GameInstanceEnemies.RemoveRange(gameInstanceEnemies);
            _gameAPIContext.GameInstances.Remove(gameInstance);
            _gameAPIContext.SaveChanges();
        }

        private void CreateGameInstance(string userId)
        {
            if (!_gameAPIContext.GameInstances.Where(gi => gi.UserId == userId).Any())
            {
                GameInstance gameInstance = new GameInstance();
                gameInstance.UserId = userId;
                _gameAPIContext.GameInstances.Add(gameInstance);

                Item item = _gameAPIContext.Items.Where(i => i.Name == "Clothes").FirstOrDefault();
                UserItem userItem = new UserItem { UserId = userId, ItemId = item.Id };
                _gameAPIContext.UserItems.Add(userItem);

                item = _gameAPIContext.Items.Where(i => i.Name == "Wooden Sword").FirstOrDefault();
                userItem = new UserItem { UserId = userId, ItemId = item.Id };
                _gameAPIContext.UserItems.Add(userItem);

                Enemy enemy = _gameAPIContext.Enemies.Where(e => e.Name == "Silver Dragon").FirstOrDefault();
                _gameAPIContext.GameInstanceEnemies.Add(new GameInstanceEnemy { GameInstanceId = gameInstance.Id, EnemyId = enemy.Id, Health = 20000 });

                _gameAPIContext.SaveChanges();
            }
        }

        private static string CreateMD5Hash(string input)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);
                byte[] hashedBytes = md5.ComputeHash(inputBytes);

                System.Text.StringBuilder sb = new System.Text.StringBuilder();

                for (int i = 0; i < hashedBytes.Length; i++)
                {
                    sb.Append(hashedBytes[i].ToString("X2"));
                }

                return sb.ToString().ToLower();
            }
        }
    }
}
