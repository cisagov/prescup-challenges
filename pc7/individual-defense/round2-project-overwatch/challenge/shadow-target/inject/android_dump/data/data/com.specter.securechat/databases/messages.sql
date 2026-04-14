-- Refactored schema to match Signal app structure
CREATE TABLE conversations (
    _id INTEGER PRIMARY KEY,
    name TEXT,
    archived INTEGER DEFAULT 0,
    sort_timestamp INTEGER,
    snippet TEXT,
    snippet_type INTEGER,
    unread_count INTEGER DEFAULT 0
);

CREATE TABLE recipients (
    _id INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    type INTEGER NOT NULL,
    phone_number TEXT,
    system_display_name TEXT,
    system_contact_photo_uri TEXT
);

CREATE TABLE messages (
    _id INTEGER PRIMARY KEY,
    thread_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    date_sent INTEGER,
    date_received INTEGER,
    body TEXT,
    type INTEGER,
    read INTEGER DEFAULT 0,
    FOREIGN KEY(thread_id) REFERENCES conversations(_id)
);

CREATE TABLE attachments (
    _id INTEGER PRIMARY KEY,
    message_id INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    data BLOB NOT NULL,
    FOREIGN KEY(message_id) REFERENCES messages(_id)
);

-- Insert sample data for conversations
INSERT INTO conversations (_id, name, archived, sort_timestamp, snippet, snippet_type, unread_count) VALUES (1, 'Group Chat', 0, 1674700000, 'Hey everyone, what are the plans for the weekend?', 1, 2);
INSERT INTO conversations (_id, name, archived, sort_timestamp, snippet, snippet_type, unread_count) VALUES (2, 'Alice and Bob', 0, 1674700100, 'Can you review my presentation?', 1, 0);

-- Insert sample data for recipients
INSERT INTO recipients (_id, address, type, phone_number, system_display_name, system_contact_photo_uri) VALUES (1, 'group1', 2, NULL, 'Group Chat', NULL);
INSERT INTO recipients (_id, address, type, phone_number, system_display_name, system_contact_photo_uri) VALUES (2, 'bob', 1, '+1234567890', 'Bob', NULL);
INSERT INTO recipients (_id, address, type, phone_number, system_display_name, system_contact_photo_uri) VALUES (3, 'alice', 1, '+0987654321', 'Alice', NULL);
INSERT INTO recipients (_id, address, type, phone_number, system_display_name, system_contact_photo_uri) VALUES (4, 'jordan', 1, '+1122334455', 'Jordan', NULL);
INSERT INTO recipients (_id, address, type, phone_number, system_display_name, system_contact_photo_uri) VALUES (5, 'morgan', 1, '+2233445566', 'Morgan', NULL);
INSERT INTO recipients (_id, address, type, phone_number, system_display_name, system_contact_photo_uri) VALUES (6, 'group2', 2, NULL, 'Weekend Warriors', NULL);

-- Insert sample data for messages
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (1, 1, 'group1', 1674700200, 1674700300, 'Hey everyone, what are the plans for the weekend?', 1, 0);
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (2, 1, 'group1', 1674700400, 1674700500, 'I was thinking we could go hiking.', 1, 0);
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (3, 2, 'bob', 1674700600, 1674700700, 'Can you review my presentation?', 1, 1);
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (4, 2, 'unknown', 1674700800, 1674700900, 'Of course, send it over.', 1, 1);
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (5, 1, 'group1', 1674701000, 1674701100, 'I found a great spot for hiking. Sending the map.', 2, 0);
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (6, 1, 'jordan', 1674701200, 1674701300, 'Thanks! I will check it out.', 1, 0);
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (7, 2, 'unknown', 1674701400, 1674701500, 'Can you review the document I sent?', 2, 1);
INSERT INTO messages (_id, thread_id, address, date_sent, date_received, body, type, read) VALUES (8, 2, 'jordan', 1674701600, 1674701700, 'Sure, I will take a look.', 1, 1);

-- Add sample attachments
INSERT INTO attachments (_id, message_id, content_type, data) VALUES (1, 5, 'image/png', X'89504E470D0A1A0A0000000D49484452'); -- PNG header
INSERT INTO attachments (_id, message_id, content_type, data) VALUES (2, 7, 'application/pdf', X'255044462D312E350A25E2E3CFD30A'); -- PDF header