-- Copyright 2024 Carnegie Mellon University.
-- Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
-- root or contact permission@sei.cmu.edu for full terms.

UPDATE airlock_controls SET outer_open = $2, inner_open = $3, pressurized = $4 WHERE id = $1;
