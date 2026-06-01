<?php

class firstToken
{
  public function token()
  {
    return getenv("firstToken");
  }
}

class secondToken
{
  // You'll need this... Good luck!
  public function initDB()
  {
    $dsn  = 'mysql:host=database;dbname=pop;charset=utf8mb4';
    $user = 'user';
    $pass = getenv("DB_PASS");

    try{
      return new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
      ]);
    } catch (PDOException $e) {
      echo "<h1>Database connection failed (container network may be initializing). If the issue persists after a few minutes, please contact support. </h1>";
      return null;
    }
  }
}

$tokenCount = -1;
$tokenExpected = 0;
$tokenLimit = random_int(50, 100);

class thirdToken
{
 public function call0()
  {
    global $tokenExpected;
    global $tokenCount;
    global $tokenLimit;

    if ($tokenExpected != 0 || $tokenExpected == -1)
      die();

    $tokenExpected = random_int(0, 1);
    $tokenCount++;

    if($tokenCount >= $tokenLimit){
      $tokenExpected = -1;
    }

    return $tokenExpected;
  }

  public function call1()
  {
    global $tokenExpected;
    global $tokenCount;
    global $tokenLimit;

    if ($tokenExpected != 1 || $tokenExpected == -1)
      die();

    $tokenExpected = random_int(0, 1);
    $tokenCount++;

    if($tokenCount >= $tokenLimit){
      $tokenExpected = -1;
    }

    return $tokenExpected;
  }

  public function done()
  {
    global $tokenCount;
    global $tokenLimit;

    if ($tokenCount >= $tokenLimit) {
      return getenv("thirdToken");
    }

    return 0;
  }
}

class Logger
{
  public string $logFile = "/home/user/logs";

  public function log($msg)
  {
    file_put_contents("$this->logFile/log.txt", "$msg\n");
  }

  // TODO: We want to save all imported mazes as potential samples
  // Right now, just pass through. Useless at the moment
  public function logImport($import)
  {

    return $import;
  }
}

// Stack used by the DFS algorithm
class GlobalStack
{
  private static array $stack = [];

  public static function push($value)
  {
    self::$stack[] = $value;
    return $value;
  }

  public static function pop()
  {
    if (empty(self::$stack)) {
      throw new UnderflowException('Stack is empty');
    }
    return array_pop(self::$stack);
  }

  public static function peek()
  {
    if (empty(self::$stack)) {
      throw new UnderflowException('Stack is empty');
    }
    return self::$stack[count(self::$stack) - 1];
  }

  public static function isEmpty()
  {
    return self::$stack === [];
  }

  public static function size()
  {
    return count(self::$stack);
  }

  public static function clear()
  {
    self::$stack = [];
  }
}

class Benchmark
{
  private static $t0 = null; // hrtime in ns
  private static $t1 = null;

  public static function startTimer()
  {
    self::$t0 = hrtime(true);
    self::$t1 = null;
  }

  public static function stopTimer()
  {
    if (self::$t0 === null) {
      throw new RuntimeException('Timer was not started.');
    }
    self::$t1 = hrtime(true);
  }

  /**
   * Returns the execution time; renamed from length to avoid confusion with path length
   */
  public function execute()
  {
    $elapsedNs = (self::$t1 ?? hrtime(true)) - (self::$t0 ?? hrtime(true));
    return $elapsedNs / 1e6;
  }

  /** Length of a path: number of moves (edges). */
  public function pathLength($path)
  {
    // Path like [[x,y], [x2,y2], ...]
    $n = count($path);
    if ($n <= 1) return 0;

    // Ignore zero-length repeats
    $moves = 0;
    for ($i = 1; $i < $n; $i++) {
      if ($path[$i][0] !== $path[$i - 1][0] || $path[$i][1] !== $path[$i - 1][1]) {
        $moves++;
      }
    }
    return $moves;
  }

  public function turns($path)
  {
    $n = count($path);
    if ($n <= 2) return 0;

    $prevDir = null; // [dx, dy] normalized to -1/0/1
    $turns = 0;

    for ($i = 1; $i < $n; $i++) {
      [$x1, $y1] = $path[$i - 1];
      [$x2, $y2] = $path[$i];

      $dx = $x2 - $x1;
      $dy = $y2 - $y1;

      // Skip zero-length steps
      if ($dx === 0 && $dy === 0) continue;

      // Normalize to unit step in grid (assumes orthogonal moves)
      if ($dx !== 0) $dx = $dx < 0 ? -1 : 1;
      if ($dy !== 0) $dy = $dy < 0 ? -1 : 1;

      $dir = [$dx, $dy];

      if ($prevDir !== null && ($dir[0] !== $prevDir[0] || $dir[1] !== $prevDir[1])) {
        $turns++;
      }
      $prevDir = $dir;
    }

    return $turns;
  }
}

class Defaults
{
  public function getSampleBuilder()
  {
    return new MazeBuilder();
  }

  // The color of the normal spaces
  public function ok()
  {
    return "#f3f3cfff";
  }
  public function wall()
  {
    return "#222";
  }
  public function start()
  {
    return "#2a9d8f";
  }
  public function goal()
  {
    return "#e76f51";
  }
  public function path()
  {
    return "#90be6d";
  }

  // Unused at the moment; we only show the final solution
  public function seen()
  {
    return "#cde7ff";
  }
}

class Announcer
{
  public string $successMessage = "MAZE SOLVED";
  public string $failureMessage = "NO PATH";

  // You can redraw UI here; for demo we print a banner the client styles.
  // For example, in the future we would like to add step by step solution displays.
  public function handle($msg): void
  {
    echo '<div id="banner" data-msg="' . htmlspecialchars($msg, ENT_QUOTES) . '"></div>';
  }
}

class Solver
{
  public function __construct(public $a) {}

  public function goal_reached($arg)
  {
    if ($arg == GlobalStack::peek()) {
      $this->a->handle($this->a->successMessage);
    } else {
      $this->a->handle($this->a->failureMessage);
    }
  }

  /**
   * DFS using GlobalStack. Maze: 0=open, 1=wall. start/goal: [r,c]
   * Returns path (list of [r,c]) or null.
   */
  public function dfs($maze, $start, $goal)
  {
    if ($maze == null || $start == null || $goal == null) {
      return null;
    }
    $H = count($maze);
    $W = count($maze[0] ?? []);
    if ($H === 0 || $W === 0) {
      GlobalStack::push('NOPE');
      $this->goal_reached('GOAL');
      return null;
    }

    // Visited grid and integer parent pointers (-1 = none)
    $seen = array_fill(0, $H, array_fill(0, $W, false));
    $parR = array_fill(0, $H, array_fill(0, $W, -1));
    $parC = array_fill(0, $H, array_fill(0, $W, -1));

    $inBounds = static fn(int $r, int $c) => $r >= 0 && $c >= 0 && $r < $H && $c < $W;

    GlobalStack::clear();
    GlobalStack::push($start);

    while (!GlobalStack::isEmpty()) {
      [$r, $c] = GlobalStack::pop();

      if (!$inBounds($r, $c)) continue;
      if ($maze[$r][$c] === 1 || $seen[$r][$c]) continue;

      $seen[$r][$c] = true;

      if ($r === $goal[0] && $c === $goal[1]) {
        // Reconstruct path from goal back to start using parent pointers
        $path = [];
        $cr = $goal[0];
        $cc = $goal[1];
        $limit = $H * $W; // safety cap

        while ($limit-- > 0) {
          $path[] = [$cr, $cc];
          if ($cr === $start[0] && $cc === $start[1]) break;
          $pr = $parR[$cr][$cc];
          $pc = $parC[$cr][$cc];
          if ($pr === -1 || $pc === -1) {
            $path = null;
            break;
          }
          $cr = $pr;
          $cc = $pc;
        }

        if ($path !== null) {
          $path = array_reverse($path);
          GlobalStack::push('GOAL');
          $this->goal_reached('GOAL');
          return $path;
        }

        // Broken parent chain ⇒ treat as failure
        GlobalStack::push('NOPE');
        $this->goal_reached('GOAL');
        return null;
      }

      // Explore neighbors (down, up, right, left) — DFS via explicit stack
      $nbrs = [[$r + 1, $c], [$r - 1, $c], [$r, $c + 1], [$r, $c - 1]];
      foreach ($nbrs as [$nr, $nc]) {
        if ($inBounds($nr, $nc) && $maze[$nr][$nc] === 0 && !$seen[$nr][$nc]) {
          if ($parR[$nr][$nc] === -1 && !($nr === $start[0] && $nc === $start[1])) {
            $parR[$nr][$nc] = $r;
            $parC[$nr][$nc] = $c;
          }
          GlobalStack::push([$nr, $nc]);
        }
      }
    }

    // No path found
    GlobalStack::push('NOPE');
    $this->goal_reached('GOAL');
    return null;
  }
}

// A short collection of some fun maze samples
class MazeBuilder
{
  public $maze = array(
    "maze" => array(0 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0, 15 => 0, 16 => 0, 17 => 0, 18 => 0, 19 => 1,), 1 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 1, 9 => 1, 10 => 1, 11 => 0, 12 => 1, 13 => 1, 14 => 1, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 1,), 2 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 1, 13 => 0, 14 => 0, 15 => 0, 16 => 1, 17 => 0, 18 => 0, 19 => 0,), 3 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 1, 11 => 1, 12 => 1, 13 => 0, 14 => 1, 15 => 0, 16 => 1, 17 => 1, 18 => 1, 19 => 0,), 4 => array(0 => 1, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 0, 16 => 0, 17 => 0, 18 => 0, 19 => 0,), 5 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 1, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 1, 13 => 1, 14 => 0, 15 => 1, 16 => 1, 17 => 1, 18 => 1, 19 => 1,), 6 => array(0 => 0, 1 => 1, 2 => 1, 3 => 1, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 0, 13 => 0, 14 => 0, 15 => 0, 16 => 0, 17 => 0, 18 => 0, 19 => 0,), 7 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 1, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 1, 14 => 0, 15 => 1, 16 => 0, 17 => 1, 18 => 0, 19 => 1,), 8 => array(0 => 0, 1 => 1, 2 => 1, 3 => 1, 4 => 0, 5 => 1, 6 => 1, 7 => 1, 8 => 0, 9 => 1, 10 => 1, 11 => 1, 12 => 1, 13 => 0, 14 => 0, 15 => 1, 16 => 0, 17 => 0, 18 => 0, 19 => 1,), 9 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 1, 16 => 1, 17 => 1, 18 => 1, 19 => 1,), 10 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 1, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 1, 13 => 1, 14 => 0, 15 => 0, 16 => 0, 17 => 1, 18 => 0, 19 => 0,), 11 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 0, 13 => 0, 14 => 0, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 12 => array(0 => 1, 1 => 1, 2 => 1, 3 => 1, 4 => 1, 5 => 1, 6 => 1, 7 => 0, 8 => 0, 9 => 1, 10 => 0, 11 => 0, 12 => 0, 13 => 1, 14 => 1, 15 => 0, 16 => 1, 17 => 0, 18 => 0, 19 => 0,), 13 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 1, 11 => 1, 12 => 1, 13 => 0, 14 => 0, 15 => 0, 16 => 0, 17 => 0, 18 => 1, 19 => 0,), 14 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 1, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 0, 14 => 1, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 15 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 0, 13 => 1, 14 => 0, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 16 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 1, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 1, 14 => 0, 15 => 0, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 17 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 1, 5 => 1, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 1, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 0, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 18 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 1, 11 => 0, 12 => 1, 13 => 0, 14 => 1, 15 => 0, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 19 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 0, 16 => 0, 17 => 0, 18 => 1, 19 => 0,),),
    "start" => array(0 => 0, 1 => 0,),
    "goal" => array(0 => 19, 1 => 19,)
  );

  public $impossible = array(
    "maze" => array(0 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0, 15 => 0, 16 => 0, 17 => 0, 18 => 0, 19 => 1,), 1 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 1, 9 => 1, 10 => 1, 11 => 0, 12 => 1, 13 => 1, 14 => 1, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 1,), 2 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 1, 13 => 0, 14 => 0, 15 => 0, 16 => 1, 17 => 0, 18 => 0, 19 => 0,), 3 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 1, 11 => 1, 12 => 1, 13 => 0, 14 => 1, 15 => 0, 16 => 1, 17 => 1, 18 => 1, 19 => 0,), 4 => array(0 => 1, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 0, 16 => 0, 17 => 0, 18 => 0, 19 => 0,), 5 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 1, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 1, 13 => 1, 14 => 0, 15 => 1, 16 => 1, 17 => 1, 18 => 1, 19 => 1,), 6 => array(0 => 0, 1 => 1, 2 => 1, 3 => 1, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 0, 13 => 0, 14 => 0, 15 => 0, 16 => 0, 17 => 0, 18 => 0, 19 => 0,), 7 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 1, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 1, 14 => 0, 15 => 1, 16 => 0, 17 => 1, 18 => 0, 19 => 1,), 8 => array(0 => 0, 1 => 1, 2 => 1, 3 => 1, 4 => 0, 5 => 1, 6 => 1, 7 => 1, 8 => 0, 9 => 1, 10 => 1, 11 => 1, 12 => 1, 13 => 0, 14 => 0, 15 => 1, 16 => 0, 17 => 0, 18 => 0, 19 => 1,), 9 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 1, 16 => 1, 17 => 1, 18 => 1, 19 => 1,), 10 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 1, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 1, 13 => 1, 14 => 0, 15 => 0, 16 => 0, 17 => 1, 18 => 0, 19 => 0,), 11 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 0, 13 => 0, 14 => 0, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 12 => array(0 => 1, 1 => 1, 2 => 1, 3 => 1, 4 => 1, 5 => 1, 6 => 1, 7 => 0, 8 => 0, 9 => 1, 10 => 0, 11 => 0, 12 => 0, 13 => 1, 14 => 1, 15 => 0, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 13 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 1, 11 => 1, 12 => 1, 13 => 0, 14 => 0, 15 => 0, 16 => 0, 17 => 0, 18 => 1, 19 => 0,), 14 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 1, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 0, 14 => 1, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 15 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 1, 10 => 0, 11 => 1, 12 => 0, 13 => 1, 14 => 0, 15 => 1, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 16 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 1, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 1, 14 => 0, 15 => 0, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 17 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 1, 5 => 1, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 1, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 0, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 18 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 1, 11 => 0, 12 => 1, 13 => 0, 14 => 1, 15 => 0, 16 => 1, 17 => 0, 18 => 1, 19 => 0,), 19 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 1, 15 => 0, 16 => 0, 17 => 0, 18 => 1, 19 => 0,),),
    "start" => array(0 => 0, 1 => 0,),
    "goal" => array(0 => 19, 1 => 19,)
  );

  public $smiley = array(
    "maze" => array(0 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0,), 1 => array(0 => 0, 1 => 1, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 1, 9 => 0,), 2 => array(0 => 0, 1 => 1, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 1, 9 => 0,), 3 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0,), 4 => array(0 => 1, 1 => 1, 2 => 1, 3 => 1, 4 => 0, 5 => 0, 6 => 1, 7 => 1, 8 => 1, 9 => 1,), 5 => array(0 => 1, 1 => 0, 2 => 0, 3 => 1, 4 => 1, 5 => 1, 6 => 1, 7 => 0, 8 => 0, 9 => 1,), 6 => array(0 => 1, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 1, 6 => 0, 7 => 0, 8 => 1, 9 => 1,), 7 => array(0 => 0, 1 => 1, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 1, 9 => 0,), 8 => array(0 => 0, 1 => 0, 2 => 1, 3 => 1, 4 => 1, 5 => 1, 6 => 1, 7 => 1, 8 => 0, 9 => 0,), 9 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0,),),
    "start" => array(0 => 5, 1 => 1,),
    "goal" => array(0 => 5, 1 => 8,)
  );

  public $heart = array(
    "maze" => array(0 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0,), 1 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 0,), 2 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0,), 3 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 0, 7 => 1, 8 => 0,), 4 => array(0 => 0, 1 => 1, 2 => 1, 3 => 0, 4 => 1, 5 => 0, 6 => 1, 7 => 1, 8 => 0,), 5 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 0,), 6 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 1, 5 => 1, 6 => 0, 7 => 0, 8 => 0,), 7 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 0, 7 => 0, 8 => 0,), 8 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0,),),
    "start" => array(0 => 2, 1 => 2,),
    "goal" => array(0 => 2, 1 => 6,),
  );

  public $field = array(
    "maze" => array(0 => array(0 => 0, 1 => 1, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 1, 10 => 1, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 1 => array(0 => 1, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 1, 7 => 1, 8 => 0, 9 => 0, 10 => 1, 11 => 1, 12 => 0, 13 => 0, 14 => 0,), 2 => array(0 => 1, 1 => 1, 2 => 1, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 0, 11 => 1, 12 => 1, 13 => 0, 14 => 0,), 3 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 1, 11 => 0, 12 => 1, 13 => 1, 14 => 1,), 4 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 1, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 1,), 5 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 1, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 1, 14 => 0,), 6 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 1, 13 => 0, 14 => 0,), 7 => array(0 => 0, 1 => 1, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 1, 14 => 0,), 8 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 1, 7 => 0, 8 => 1, 9 => 0, 10 => 0, 11 => 0, 12 => 1, 13 => 0, 14 => 0,), 9 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 1, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 1, 11 => 0, 12 => 1, 13 => 0, 14 => 0,), 10 => array(0 => 1, 1 => 1, 2 => 1, 3 => 1, 4 => 1, 5 => 1, 6 => 1, 7 => 1, 8 => 1, 9 => 1, 10 => 1, 11 => 1, 12 => 1, 13 => 1, 14 => 1,), 11 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 12 => array(0 => 1, 1 => 1, 2 => 1, 3 => 1, 4 => 1, 5 => 1, 6 => 1, 7 => 1, 8 => 1, 9 => 1, 10 => 1, 11 => 1, 12 => 1, 13 => 1, 14 => 1,), 13 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 14 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,),),
    "start" => array(0 => 11, 1 => 0,),
    "goal" => array(0 => 11, 1 => 14,)
  );

  public $bunny = array(
    "maze" => array(0 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 1 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 1, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 2 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 3 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 4 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 1, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 5 => array(0 => 0, 1 => 0, 2 => 1, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 6 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 1, 9 => 1, 10 => 1, 11 => 0, 12 => 1, 13 => 0, 14 => 0,), 7 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 1, 14 => 0,), 8 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 1, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 1, 13 => 0, 14 => 0,), 9 => array(0 => 0, 1 => 1, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 1, 13 => 0, 14 => 0,), 10 => array(0 => 0, 1 => 0, 2 => 1, 3 => 1, 4 => 1, 5 => 0, 6 => 0, 7 => 0, 8 => 1, 9 => 1, 10 => 0, 11 => 0, 12 => 1, 13 => 0, 14 => 0,), 11 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 0, 5 => 0, 6 => 1, 7 => 1, 8 => 0, 9 => 0, 10 => 0, 11 => 1, 12 => 0, 13 => 0, 14 => 0,), 12 => array(0 => 0, 1 => 0, 2 => 0, 3 => 1, 4 => 1, 5 => 1, 6 => 0, 7 => 1, 8 => 1, 9 => 1, 10 => 1, 11 => 0, 12 => 0, 13 => 0, 14 => 0,), 13 => array(0 => 0, 1 => 0, 2 => 0, 3 => 0, 4 => 0, 5 => 0, 6 => 0, 7 => 0, 8 => 0, 9 => 0, 10 => 0, 11 => 0, 12 => 0, 13 => 0, 14 => 0,),),
    "start" => array(0 => 13, 1 => 0,),
    "goal" => array(0 => 13, 1 => 14,)
  );

  public function prepare($name)
  {
    $maze = $this->maze;
    if ($name == "impossible") {
      $maze = $this->impossible;
    } else if ($name == "smiley") {
      $maze = $this->smiley;
    } else if ($name == "heart") {
      $maze = $this->heart;
    } else if ($name == "field") {
      $maze = $this->field;
    } else if ($name == "bunny") {
      $maze = $this->bunny;
    }

    return new Maze($maze['maze'], $maze['start'], $maze['goal']);
  }

  // This currently doesn't work right, as the start/goal gets turned into walls
  // Will be a cool feature in the future though
  // Easiest solution would be to make "new Maze" force start/goal to be open
  public function invertMaze($maze){
    $newMaze = [];
    foreach($maze as $row){
      $newRow = [];
      foreach($row as $col){
        if($col == 1){
          $col = 0;
        } else if($col == 0){
          $col = 1;
        }
        $newRow[] = $col;
      }
      $newMaze[] = $newRow;
    }

    return $newMaze;
  }
}

class Maze
{
  public $solution = null;
  public function __construct(public $maze, public $start, public $goal) {}

  public function handle($goal = null)
  {
    if ($goal == null) {
      $goal = $this->goal;
    }

    $solver = new Solver(new Announcer());
    
    Benchmark::startTimer();
    $this->solution = $solver->dfs($this->maze, $this->start, $goal);
    Benchmark::stopTimer();
    return $this;
  }

  public static function dump($maze = null)
  {
    if (is_array($maze)) {
      return "MAZE DEBUG: " . print_r($maze, true);
    }
  }
}

class Importer
{

  public $test;
  public $callClass;
  public $callback;

  public function handle($raw)
  {
    $allowed = ["GlobalStack", "firstToken", "secondToken", "thirdToken", "Logger", 
                "Benchmark", "Defaults", "Announcer", "Solver", "MazeBuilder", "Maze", 
                "Importer", "debugPanel", "Post"];
    $result = @unserialize($raw, ['allowed_classes' => $allowed]);
    if ($result === false && $raw !== 'b:0;') {
      fwrite(STDERR, "Unserialize failed\n");
      exit(2);
    }

    $new = $result->handle($result->goal);

    return $this->callClass->{$this->callback}($new);
  }
}

class debugPanel
{
  public static function emitDebugPanel($maze)
  {
    if (!isset($_COOKIE['debug'])) {
      return;
    }

    $bm = new Benchmark();

    $executionTime = self::getExecutionTime($bm);

    $solution = $maze->solution ?? [];
    $length = $bm->pathLength($solution);
    $turns  = $bm->turns($solution);

    $grid   = $maze->maze ?? [];
    $rows   = is_array($grid) ? count($grid) : 0;
    $cols   = ($rows && is_array($grid[0])) ? count($grid[0]) : 0;

    $start  = $maze->start  ?? null;
    $goal   = $maze->goal   ?? null;

    $toJson = static function ($value): string {
      $json = json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
      return htmlspecialchars($json === false ? 'null' : $json, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };
    $toText = static function ($value): string {
      return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };

    echo '<section class="debug-panel" style="font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif; border:1px solid #ccc; border-radius:8px; padding:12px; margin:12px 0;">';

    echo '<header style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">';
    echo '  <h3 style="margin:0; font-size:16px;">Debug Panel</h3>';
    echo '  <span style="font-size:12px; color:#666;">', $toText(date('Y-m-d H:i:s')), '</span>';
    echo '</header>';

    echo '<div class="metrics" style="display:flex; gap:12px; flex-wrap:wrap; margin-bottom:8px;">';
    echo '  <div style="padding:6px 8px; background:#f6f6f6; border-radius:6px;">⏱️ Exec: <strong>', $toText(number_format((float)$executionTime, 3)), ' ms</strong></div>';
    echo '  <div style="padding:6px 8px; background:#f6f6f6; border-radius:6px;">📏 Length: <strong>', $toText((string)$length), '</strong></div>';
    echo '  <div style="padding:6px 8px; background:#f6f6f6; border-radius:6px;">↩️ Turns: <strong>', $toText((string)$turns), '</strong></div>';
    echo '  <div style="padding:6px 8px; background:#f6f6f6; border-radius:6px;">🧱 Grid: <strong>', $toText("{$cols}×{$rows}"), '</strong></div>';
    echo '</div>';

    echo '<ul style="margin:6px 0 12px 18px; padding:0; line-height:1.5;">';
    echo '  <li>Start: <code>', $toText($start !== null ? json_encode($start) : 'null'), '</code></li>';
    echo '  <li>Goal: <code>',  $toText($goal  !== null ? json_encode($goal)  : 'null'), '</code></li>';
    echo '  <li>Solution steps: <code>', $toText((string)count($solution)), '</code></li>';
    echo '</ul>';

    echo '<details style="margin-bottom:6px;"><summary style="cursor:pointer;">Maze array</summary>';
    echo '  <pre style="white-space:pre; overflow:auto; margin:8px 0 0;">', $toJson($grid), '</pre>';
    echo '</details>';

    echo '<details style="margin-bottom:6px;"><summary style="cursor:pointer;">Start</summary>';
    echo '  <pre style="white-space:pre; overflow:auto; margin:8px 0 0;">', $toJson($start), '</pre>';
    echo '</details>';

    echo '<details style="margin-bottom:6px;"><summary style="cursor:pointer;">Goal</summary>';
    echo '  <pre style="white-space:pre; overflow:auto; margin:8px 0 0;">', $toJson($goal), '</pre>';
    echo '</details>';

    echo '<details style="margin-bottom:0;"><summary style="cursor:pointer;">Solution</summary>';
    echo '  <pre style="white-space:pre; overflow:auto; margin:8px 0 0;">', $toJson($solution), '</pre>';
    echo '</details>';

    echo '</section>';
  }

  public static function getExecutionTime($benchmark)
  {
    if (!isset($_COOKIE['debug'])) {
      return;
    }
    return $benchmark->execute();
  }
}

class Post
{
  public static $MazeBuilder;

  public function handle()
  {
    $payload = $_POST['payload'] ?? '';
    $data = json_decode($payload, true);

    if (is_array($data) && isset($data['maze'], $data['start'], $data['goal'])) {

      $maze = new Maze($data['maze'], $data['start'], $data['goal']);
      $maze->handle();

      return $maze;
    } else if ($_POST['sample']) {
      $defaults = new Defaults();
      $this->assignSampleBuilder($defaults->getSampleBuilder());
      $maze = $this->createSample('sample');
      $maze->handle();

      return $maze;
    } else if ($_POST['import']) {
      return $this->import("import");
    } else {
      // bad payload — handled client-side visually
      return null;
    }
  }

  public function createSample($name)
  {
    if(is_string($name))
      return self::$MazeBuilder->prepare($_POST[$name]);
    die();
  }

  public function assignSampleBuilder($builder)
  {
    self::$MazeBuilder = $builder;
  }

  public function import($var)
  {
    $importer = new Importer();

    $importer->callClass = new Logger();
    $importer->callback = "logImport";

    return $importer->handle($_POST[$var]);
  }
}

/* ============================
   Handle POST (solve request)
   ============================ */
$maze = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $post_handler = new Post();
  $maze = $post_handler->handle();
}

/* ============================
Emit page (UI + result)
============================ */
?>
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ScaraMalware's Funhouse</title>
  <style>
    :root {
      --cell: 28px;
      --gap: 2px;
      <?php $default_colors = new Defaults(); ?>--ok: <?php echo $default_colors->ok(); ?>;
      --wall: <?php echo $default_colors->wall(); ?>;
      --start: <?php echo $default_colors->start(); ?>;
      --goal: <?php echo $default_colors->goal(); ?>;
      --path: <?php echo $default_colors->path(); ?>;
      --seen: <?php echo $default_colors->seen(); ?>;
    }

    body {
      font-family: system-ui, sans-serif;
      margin: 20px;
    }

    h1 {
      margin: 0 0 10px;
    }

    .controls {
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }

    .actions {
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }

    .actions form {
      display: flex;
      gap: 8px;
      align-items: center;
      margin: 0;
    }

    .actions select,
    .actions button {
      line-height: 1.2;
    }

    label {
      display: flex;
      align-items: center;
      gap: 6px;
    }

    #grid {
      display: grid;
      gap: var(--gap);
      margin-top: 10px;
    }

    .cell {
      width: var(--cell);
      height: var(--cell);
      background: var(--ok);
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      user-select: none;
      font-size: 12px;
    }

    .wall {
      background: var(--wall);
    }

    .start {
      background: var(--start);
      color: #fff;
    }

    .goal {
      background: var(--goal);
      color: #fff;
    }

    .path {
      background: var(--path) !important;
    }

    .legend {
      display: flex;
      gap: 10px;
      align-items: center;
      margin-top: 10px;
    }

    .swatch {
      width: 16px;
      height: 16px;
      border-radius: 4px;
      display: inline-block;
      vertical-align: middle;
      margin-right: 6px;
    }

    .bar {
      display: flex;
      gap: 10px;
      align-items: center;
      margin: 8px 0;
    }

    button {
      padding: 8px 12px;
      border-radius: 8px;
      border: 1px solid #ccc;
      background: #f6f6f6;
      cursor: pointer;
    }

    button:hover {
      background: #eee;
    }

    .banner {
      margin: 12px 0;
      padding: 10px 12px;
      border-radius: 10px;
    }

    .ok {
      background: #e8f7f0;
      border: 1px solid #9adbb7;
      color: #1e6b4e;
    }

    .bad {
      background: #fdecea;
      border: 1px solid #f5b5ae;
      color: #b02a1a;
    }

    .note {
      color: #666;
      font-size: 12px;
    }

    .hidden {
      display: none;
    }
  </style>
</head>

<body>
  <h1>ScaraMalware's Funhouse</h1>

  <div class="controls">
    <label>Width <input type="number" id="w" min="2" max="64" value="12"></label>
    <label>Height <input type="number" id="h" min="2" max="64" value="8"></label>
    <button id="build">Build Grid</button>
    <div class="bar">
      <label><input type="radio" name="tool" value="wall" checked> Draw walls</label>
      <label><input type="radio" name="tool" value="start"> Set start</label>
      <label><input type="radio" name="tool" value="goal"> Set goal</label>
      <button id="clearWalls">Clear walls</button>
    </div>
  </div>

  <div class="actions">
    <form id="solveForm" method="post" style="display:inline-block; margin-right:8px;">
      <input type="hidden" name="payload" id="payload">
      <button type="submit">Solve with DFS</button>
    </form>

    <form id="sampleForm" method="post" style="display:inline-block;">
      <div class="bar">
        <label>
          Sample
          <select name="sample" id="sample">
            <option value="maze">large maze</option>
            <option value="impossible">impossible</option>
            <option value="smiley">smiley</option>
            <option value="heart">heart</option>
            <option value="field">field</option>
            <option value="bunny">bunny</option>
          </select>
        </label>
        <button type="submit">Build Sample</button>
      </div>
    </form>
  </div>

  <div class="legend">
    <span><span class="swatch" style="background:var(--ok)"></span>Open</span>
    <span><span class="swatch" style="background:var(--wall)"></span>Wall</span>
    <span><span class="swatch" style="background:var(--start)"></span>Start</span>
    <span><span class="swatch" style="background:var(--goal)"></span>Goal</span>
    <span><span class="swatch" style="background:var(--path)"></span>Path</span>
  </div>

  <div id="bannerHost"></div>
  <div id="grid"></div>

  <?php if ($maze !== null): ?>
    <script>
      // Server embedded solution (if any), so we can paint the path overlay
      const serverResult = {
        maze: <?php echo json_encode($maze->maze); ?>,
        start: <?php echo json_encode($maze->start); ?>,
        goal: <?php echo json_encode($maze->goal); ?>,
        <?php if ($maze->solution !== null): ?>
          path: <?php echo json_encode($maze->solution); ?>,
        <?php else: ?>
          path: null,
        <?php endif; ?>
      };
    </script>
  <?php endif; ?>

  <script>
    (() => {
      const gridEl = document.getElementById('grid');
      const wEl = document.getElementById('w');
      const hEl = document.getElementById('h');
      const payloadEl = document.getElementById('payload');
      const formEl = document.getElementById('solveForm');
      const bannerHost = document.getElementById('bannerHost');

      let W = 12,
        H = 8;
      let maze = []; // 0=open, 1=wall
      let start = [0, 0];
      let goal = [H - 1, W - 1];
      let tool = 'wall';

      function buildEmpty() {
        maze = Array.from({
          length: H
        }, () => Array.from({
          length: W
        }, () => 0));
        start = [0, 0];
        goal = [H - 1, W - 1];
      }

      function paint(path = null) {
        gridEl.style.gridTemplateColumns = `repeat(${W}, var(--cell))`;
        gridEl.innerHTML = '';
        const pathSet = new Set((path || []).map(([r, c]) => `${r},${c}`));

        for (let r = 0; r < H; r++) {
          for (let c = 0; c < W; c++) {
            const div = document.createElement('div');
            div.className = 'cell';
            if (maze[r][c] === 1) div.classList.add('wall');
            if (r === start[0] && c === start[1]) div.classList.add('start');
            if (r === goal[0] && c === goal[1]) div.classList.add('goal');
            if (pathSet.has(`${r},${c}`)) div.classList.add('path');

            div.dataset.r = r;
            div.dataset.c = c;
            div.addEventListener('click', onCell);
            gridEl.appendChild(div);
          }
        }
      }

      function onCell(e) {
        const r = +e.currentTarget.dataset.r,
          c = +e.currentTarget.dataset.c;
        if (tool === 'wall') {
          if (r === start[0] && c === start[1]) return;
          if (r === goal[0] && c === goal[1]) return;
          maze[r][c] = maze[r][c] ? 0 : 1;
        } else if (tool === 'start') {
          if (maze[r][c] === 1) return;
          start = [r, c];
        } else if (tool === 'goal') {
          if (maze[r][c] === 1) return;
          goal = [r, c];
        }
        paint();
      }

      // Controls
      document.getElementById('build').addEventListener('click', () => {
        W = Math.max(2, Math.min(64, +wEl.value || 12));
        H = Math.max(2, Math.min(64, +hEl.value || 8));
        buildEmpty();
        paint();
      });
      document.getElementById('clearWalls').addEventListener('click', () => {
        for (let r = 0; r < H; r++)
          for (let c = 0; c < W; c++)
            if (!(r === start[0] && c === start[1]) && !(r === goal[0] && c === goal[1])) maze[r][c] = 0;
        paint();
      });
      document.querySelectorAll('input[name="tool"]').forEach(r => {
        r.addEventListener('change', () => tool = r.value);
      });

      // Submit
      formEl.addEventListener('submit', () => {
        payloadEl.value = JSON.stringify({
          maze,
          start,
          goal
        });
      });

      // Initial
      buildEmpty();
      paint();

      // If server computed a solution, render it and the banner
      <?php if ($maze !== null): ?>
        // Sync client grid with server evaluation so you see exactly what was solved
        const d = serverResult;
        W = d.maze[0].length;
        H = d.maze.length;
        maze = d.maze;
        start = d.start;
        goal = d.goal;
        wEl.value = W;
        hEl.value = H;
        paint(d.path);

        // Pick up the server-rendered banner (from Announcer->handle)
        const serverBanner = document.getElementById('banner');
        if (serverBanner) {
          const msg = serverBanner.getAttribute('data-msg') || '';
          const ok = /SOLVED/i.test(msg);
          const div = document.createElement('div');
          div.className = 'banner ' + (ok ? 'ok' : 'bad');
          div.textContent = msg || (d.path ? 'Solved' : 'No path');
          bannerHost.innerHTML = '';
          bannerHost.appendChild(div);
          serverBanner.remove();
        }
      <?php endif; ?>
    })();
  </script>

  <?php debugPanel::emitDebugPanel($maze); ?>

</body>

</html>