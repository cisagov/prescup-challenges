-- Copyright 2024 Carnegie Mellon University.
-- Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
-- root or contact permission@sei.cmu.edu for full terms.

CREATE TABLE IF NOT EXISTS airlock_controls
(
  id          TEXT PRIMARY KEY,
  outer_open  BOOLEAN NOT NULL DEFAULT FALSE,
  inner_open  BOOLEAN NOT NULL DEFAULT FALSE,
  pressurized BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS camera_controls
(
  id          TEXT PRIMARY KEY,
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  recording   BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS environment_controls
(
  id          TEXT PRIMARY KEY,
  active      BOOLEAN NOT NULL DEFAULT TRUE,
  temperature SMALLINT NOT NULL DEFAULT 21
);

CREATE TABLE IF NOT EXISTS power_controls
(
  id          TEXT PRIMARY KEY,
  active      BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS comm_controls
(
  id          TEXT PRIMARY KEY,
  active      BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS door_controls
(
  id          TEXT PRIMARY KEY,
  open        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS hydroponics_controls
(
  id          TEXT PRIMARY KEY,
  active      BOOLEAN NOT NULL DEFAULT TRUE
)
