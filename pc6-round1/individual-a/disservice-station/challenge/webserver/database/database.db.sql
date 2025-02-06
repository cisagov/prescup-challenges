BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "users" (
	"id"	INTEGER,
	"username"	TEXT NOT NULL,
	"password"	TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "repairs" (
	"id"	INTEGER,
	"username"	TEXT NOT NULL,
	"car_model"	TEXT NOT NULL,
	"status"	TEXT NOT NULL,
	"completion_date"	TEXT NOT NULL,
	PRIMARY KEY("id")
);
CREATE TABLE IF NOT EXISTS "uploads" (
	"id"	INTEGER,
	"user_id"	INTEGER,
	"filename"	TEXT,
	"upload_date"	TEXT,
	FOREIGN KEY("user_id") REFERENCES "users"("id"),
	PRIMARY KEY("id" AUTOINCREMENT)
);
INSERT INTO "users" VALUES (1,'admin','B1gR3dF1r3+ruck!');
INSERT INTO "users" VALUES (2,'testuser','test');
INSERT INTO "repairs" VALUES (1,'admin','Honda Civic - test entry','In Progress','2024-09-30');
INSERT INTO "uploads" VALUES (1,NULL,'test','2024-09-13 16:52:31');
INSERT INTO "uploads" VALUES (2,NULL,'test','2024-09-13 16:53:10');
INSERT INTO "uploads" VALUES (3,'','test','2024-09-13 16:56:52');
INSERT INTO "uploads" VALUES (4,'','testfile.php','2024-09-16 18:30:00');
INSERT INTO "uploads" VALUES (5,'','testfile.php','2024-09-16 18:52:32');
COMMIT;
