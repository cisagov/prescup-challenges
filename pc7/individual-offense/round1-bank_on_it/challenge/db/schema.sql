CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    account_number VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    balance DECIMAL(12,2) DEFAULT 0.00,
    type ENUM('checking', 'savings', 'investment') DEFAULT 'checking',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE transfers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_account_number VARCHAR(16) NOT NULL,
    to_account_number VARCHAR(16) NOT NULL,
    amount DECIMAL(12,2) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_account_number) REFERENCES accounts(account_number),
    FOREIGN KEY (to_account_number) REFERENCES accounts(account_number)
);

INSERT INTO users (id, username, password, email, created_at) VALUES
(1, 'alice', 'e8e200002a3d78407b33f1e826421f71fc99e390', 'alice@example.com', '2023-01-23 10:51:16'), -- Th7eZq9#fU
(2, 'bob', '50b9fe21b8151f9496895aeb599985389b4dfc79', 'bob@example.com', '2024-03-14 04:50:08'), -- N1xuP$38ka
(3, 'carol', '6dded34e0598766047b05062590386aaf241e2bd', 'carol@example.com', '2024-05-06 15:44:17');  -- vpE5@m42Qd

INSERT INTO accounts (id, user_id, name, type, account_number, balance, created_at) VALUES
(1, 1, 'Alice Checking', 'checking', '85A83FED', 7336.74, '2023-01-25 11:42:46'),
(2, 1, 'Alice Savings', 'savings', '5DA0D3F1', 6820.37, '2023-01-28 11:31:11'),
(3, 2, 'Bob Checking', 'checking', 'F4E04DCE', 5937.36, '2024-03-15 14:30:57'),
(4, 2, '_TOKEN_', 'savings', '079AC20B', 1484.59, '2024-03-16 14:53:12'),
(5, 3, 'Carol Checking', 'checking', 'E5215CD8', 7404.28, '2024-05-08 17:52:56'),
(6, 3, 'Carol Savings', 'savings', '18CD34BD', 2546.14, '2024-05-09 14:33:11'),
(7, 3, 'Carol Investing', 'investment', 'B93B14BD', 7676.55, '2024-05-12 15:32:37');

INSERT INTO transfers (id, from_account_number, to_account_number, amount, timestamp) VALUES
(1, '5DA0D3F1', '85A83FED', 301.33, '2023-07-20 17:42:59'),
(2, 'F4E04DCE', '079AC20B', 462.02, '2024-03-18 21:20:43'),
(3, '18CD34BD', 'B93B14BD', 277.87, '2024-05-31 13:22:01');






