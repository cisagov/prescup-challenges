-- Copyright 2024 Carnegie Mellon University.
-- Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
-- root or contact permission@sei.cmu.edu for full terms.

UPDATE camera_controls SET active = $2, recording = $3 WHERE id = $1;
