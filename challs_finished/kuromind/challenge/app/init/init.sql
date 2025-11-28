CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS knowledge_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    tags JSON DEFAULT NULL,
    image VARCHAR(255) DEFAULT 'the_unknown.png',
    userId INT NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    isRestricted BOOLEAN DEFAULT FALSE,
    dangerLevel VARCHAR(50) DEFAULT NULL,
    reviewFeedback TEXT DEFAULT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_userId (userId),
    INDEX idx_status (status),
    INDEX idx_isRestricted (isRestricted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS drafts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    tags JSON DEFAULT NULL,
    image VARCHAR(255) DEFAULT 'the_unknown.png',
    userId INT NOT NULL,
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_userId (userId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS review_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    knowledgeId INT NOT NULL,
    operatorId INT NOT NULL,
    action VARCHAR(50) NOT NULL,
    feedback TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (knowledgeId) REFERENCES knowledge_items(id) ON DELETE CASCADE,
    FOREIGN KEY (operatorId) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_knowledgeId (knowledgeId),
    INDEX idx_operatorId (operatorId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
