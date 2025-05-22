USE web_alerts;

CREATE TABLE Alerts (
    ID INT AUTO_INCREMENT KEY,
    Title VARCHAR(100),
    Message VARCHAR(255),
    Resolved INT
);

CREATE TABLE Events (
    ID INT AUTO_INCREMENT KEY,
    Title VARCHAR(100),
    Message VARCHAR(255),
    Resolved INT
);

CREATE TABLE Token (
    TokenID INT AUTO_INCREMENT KEY,
    Token VARCHAR(100)
);

-- Fill in
INSERT INTO Alerts (Title, Message, Resolved) VALUES ('Test', 'Testing security alerts.', 0);
INSERT INTO Alerts (Title, Message, Resolved) VALUES ('WAF - Suspicious SQL Injection Attempt', 'A potential SQL injection attempt was detected.', 0);
INSERT INTO Alerts (Title, Message, Resolved) VALUES ('Admin Password Change', 'The admin password for this host has changed.', 0);
INSERT INTO Alerts (Title, Message, Resolved) VALUES ('WAF - Malicious symbols detected', 'A request has been detected with input that matches known payloads and was blocked.', 0);

INSERT INTO Events (Title, Message, Resolved) VALUES ('DBMS Update', 'The DBMS has been updated to the latest stable version.', 0);
INSERT INTO Events (Title, Message, Resolved) VALUES ('Admin Password Expiring', 'It has been 6 months since the password was updated.', 0);
