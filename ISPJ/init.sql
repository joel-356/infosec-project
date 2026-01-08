CREATE DATABASE IF NOT EXISTS message_app;
USE message_app;

-- Create app user properly (TCP-safe + Python-safe)
CREATE USER IF NOT EXISTS 'appuser'@'%' 
IDENTIFIED WITH mysql_native_password BY 'apppassword';

GRANT ALL PRIVILEGES ON message_app.* TO 'appuser'@'%';
FLUSH PRIVILEGES;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender VARCHAR(255) NOT NULL,
    receiver VARCHAR(255) NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    is_flagged BOOLEAN DEFAULT FALSE,
    flag_reasons TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender) REFERENCES users(email) ON DELETE CASCADE,
    FOREIGN KEY (receiver) REFERENCES users(email) ON DELETE CASCADE
);

INSERT INTO users (email, name) VALUES 
    ('user1@example.com', 'User One'),
    ('user2@example.com', 'User Two')
ON DUPLICATE KEY UPDATE name=name;
