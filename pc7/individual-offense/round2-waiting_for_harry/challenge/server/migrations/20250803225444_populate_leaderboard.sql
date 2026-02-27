-- Add migration script here
INSERT INTO leaderboard (name, score)
WITH RECURSIVE generate_series(value) AS (
  SELECT 1
  UNION ALL
  SELECT value+1 FROM generate_series
   WHERE value+1<=26
)
SELECT char(a+64) || char(b+64) || char(c+64) AS name, 1000000 + abs(random()) % 1000000 AS score FROM
  (SELECT value AS a FROM generate_series),
  (SELECT value AS b FROM generate_series),
  (SELECT value AS c FROM generate_series)
  order by score desc;

INSERT INTO leaderboard (name, score)
VALUES
    ('HSS', 2000000);