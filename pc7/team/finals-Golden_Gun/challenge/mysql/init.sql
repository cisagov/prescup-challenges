CREATE TABLE IF NOT EXISTS superSecretTableOfMazes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  mazeIdea VARCHAR(64) NOT NULL,
  UNIQUE KEY uniq_mazeIdea (mazeIdea)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO superSecretTableOfMazes (mazeIdea) VALUES ('dog'), ('cat'), ('turtle'), ('bigSpiral'), ('squareSpiral'), ('flower');