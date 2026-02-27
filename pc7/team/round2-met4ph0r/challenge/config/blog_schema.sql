-- Blog database schema
CREATE TABLE IF NOT EXISTS blog_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    author_id INT,
    published BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES blog_users(id)
);

CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT,
    author VARCHAR(50),
    content TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id)
);

-- Insert some data
INSERT INTO blog_users (username, password_hash, email, role) VALUES 
('scott', @BLOG_PWD, 'admin@blog.local', 'admin'),
('blog_user', @BLOG_PWD, 'user@blog.local', 'user');

INSERT INTO posts (title, content, author_id) VALUES 
('Welcome Post', 'Welcome to our vulnerable blog! This is part of the CTF challenge.', 1),
('Security Notice', 'We should probably fix our command injection vulnerabilities... someday.', 1),
('Service Integration', 'This blog service can communicate with the other services. Check the network tools!', 2);
