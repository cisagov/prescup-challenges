<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Meet the Team - Mushroom Market</title>
  <link rel="stylesheet" href="css/style.css">
  <style>
    .profile-grid {
      display: flex;
      flex-wrap: wrap;
      gap: 2rem;
      justify-content: center;
      margin-top: 2rem;
    }
    .profile {
      background: #222;
      border: 4px double #f4e242;
      border-radius: 8px;
      padding: 1rem;
      width: 250px;
      text-align: center;
      box-shadow: 4px 4px 0px #000;
      font-family: 'Press Start 2P', sans-serif;
    }
    .profile img {
      width: 100%;
      border-radius: 6px;
      margin-bottom: 1rem;
      border: 2px solid #fff;
    }
    .profile h3 {
      font-size: 1rem;
      margin: 0.5rem 0;
    }
    .profile p {
      font-size: 0.9rem;
      color: #eee;
      line-height: 1.4;
    }
  </style>
</head>
<body class="menu-bg">
  <header>
    <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="aboutus.php">About Us</a>
            <?php if (isset($_SESSION['username'])): ?>
                <a href="orders.php">My Orders</a>
                <a href="cart.php">View Cart</a>
                <a href="logout.php">Logout</a>
            <?php else: ?>
                <a href="login.php">Login</a>
                <a href="register.php">Register</a>
            <?php endif;?>
    </nav>
  </header>

  <div class="container">
    <h1 class="price-text">Meet the Team</h1>
    <div class="profile-grid">
      <?php
      $team = [
        ['chad.png', 'Chad Threatscape', 'Chief Intrusion Strategist', 'Fueled by ambition and afternoon espresso, Chad tackles every aorta-clenching challenge with agreeable obsession and robust defiance.', 'cthreatscape@mushmarket.com'],
        ['shayna.png', 'Shayna Nullbyte', 'Payload Optimization Officer', 'Amiable yet affected by absurd file structures, Shayna’s ambition lies in pushing acid scripts across backroom systems—often with enviable finesse.', 'snullbyte@mushmarket.com'],
        ['blake.png', 'Blake Sudo', 'Exploit Wrangler (Intern)', 'Buzzed on donut glaze and driven by unfiltered caffeine, Blake babbles about busily juggling exploits like a giddy baboon operating a debugger.', 'bsudo@mushmarket.com'],
        ['wesley.png', 'Wesley Forcenet', 'Zero-Day Sleuth', 'Obsessed with clandestine ops and early morning clamor, Wesley’s aptitude for anomaly detection has become the legend of our digital circus.', 'wforcenet@mushmarket.com'],
        ['felix.png', 'Felix Noptrick', 'Social Engineering Samurai', 'Gifted in the art of duplicity, Felix once persuaded a vending machine to give him all its coinage. His aptitude is enviably viral.', 'fnoptrick@mushmarket.com'],
        ['darcy.png', 'Darcy Heapou', '.NET Tamer', 'Wrangles frameworks with skillful patience. Darcy’s debugging sessions have been described as “ambiguous kung fu” in motion.', 'dheapou@mushmarket.com'],
        ['gavin.png', 'Gavin Shellshock', 'Credential Harvester', 'Fueled by a magnetic pull to chaos, Gavin’s inbox contains more password resets than your local armory. Still denies any wrongdoing audibly.', 'gshellshock@mushmarket.com'],
        ['marnie.png', 'Marnie Voidcast', 'Database Underminer', 'Specializing in atonable schema sabotage, Marnie’s presence is the digital equivalent of a polite tarantula with a master’s in recursion.', 'mvoidcast@mushmarket.com']
      ];
      foreach ($team as $member) {
        echo "<div class='profile'>";
        echo "<img src='images/team/{$member[0]}' alt='{$member[1]}' />";
        echo "<header nav a class='price-text'>{$member[1]} </header nav a>";
        echo "<p><b>{$member[2]} </b></p>";
        echo "<p><em><b>{$member[4]} </b></em></p>";
        echo "<p>{$member[3]} </p>";
        echo "</div>";
      }
      ?>
    </div>
  </div>

  <footer style="text-align:center; margin-top: 4em;">
    <p class="price-text">&copy; 2025 Mushroom Market Inc. All vulnerabilities reserved.</p>
  </footer>
</body>
</html>
