CREATE DATABASE IF NOT EXISTS phishing_db;
USE phishing_db;
CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048),
    prediction VARCHAR(50),
    confidence FLOAT,
    vt TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(150) UNIQUE,
    password VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user'
);
