using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace _2048_Clone
{
    public class TileColors
    {
        /// <summary>
        /// The console background colour of the tile.
        /// </summary>
        public ConsoleColor BackgroundColor { get; private set; }

        /// <summary>
        /// The console foreground colour of the tile.
        /// </summary>
        public ConsoleColor ForegroundColor { get; private set; }

        /// <summary>
        /// Dictionary of known tile numbers with a TileColors value.
        /// </summary>
        private static readonly Dictionary<int, TileColors> _colors = new Dictionary<int, TileColors>();

        /// <summary>
        /// Colours to use for a blank cell.
        /// </summary>
        private static readonly TileColors _blankColor;

        /// <summary>
        /// Colours to use if the cell has an unknown number.
        /// </summary>
        private static readonly TileColors _defaultColor;

        /// <summary>
        /// Initialise all the tile colours.
        /// </summary>
        static TileColors()
        {
            _blankColor = new TileColors(ConsoleColor.Black, ConsoleColor.DarkGray);

            _colors.Add(2, new TileColors(ConsoleColor.DarkRed, ConsoleColor.White));
            _colors.Add(4, new TileColors(ConsoleColor.DarkYellow, ConsoleColor.White));
            _colors.Add(8, new TileColors(ConsoleColor.DarkGreen, ConsoleColor.White));
            _colors.Add(16, new TileColors(ConsoleColor.DarkCyan, ConsoleColor.White));
            _colors.Add(32, new TileColors(ConsoleColor.DarkBlue, ConsoleColor.White));
            _colors.Add(64, new TileColors(ConsoleColor.DarkMagenta, ConsoleColor.White));
            _colors.Add(128, new TileColors(ConsoleColor.Red, ConsoleColor.White));
            _colors.Add(256, new TileColors(ConsoleColor.Yellow, ConsoleColor.Black));
            _colors.Add(512, new TileColors(ConsoleColor.Green, ConsoleColor.Black));
            _colors.Add(1024, new TileColors(ConsoleColor.Cyan, ConsoleColor.Black));
            _colors.Add(2048, new TileColors(ConsoleColor.Blue, ConsoleColor.White));

            _defaultColor = new TileColors(ConsoleColor.Magenta, ConsoleColor.White);
        }

        /// <summary>
        /// Construct a TileColors instance with the given background and foreground colours.
        /// </summary>
        /// <param name="backgroundColor">Background colour of the tile.</param>
        /// <param name="foregroundColor">Foreground colour of the tile.</param>
        private TileColors(ConsoleColor backgroundColor, ConsoleColor foregroundColor)
        {
            BackgroundColor = backgroundColor;
            ForegroundColor = foregroundColor;
        }

        /// <summary>
        /// Method to call for getting the TileColors for the specified tile number.
        /// </summary>
        /// <param name="tileNumber">Tile number to lookup.</param>
        /// <returns>TileColors instance for the given tile number.</returns>
        public static TileColors GetTileColors(int tileNumber)
        {
            if (tileNumber == 0)
            {
                return _blankColor;
            }

            TileColors color;
            bool found = _colors.TryGetValue(tileNumber, out color);

            if (found)
            {
                return color;
            }
            else
            {
                return _defaultColor;
            }
        }
    }
}
