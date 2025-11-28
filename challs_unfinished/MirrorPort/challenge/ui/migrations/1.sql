
CREATE TABLE teas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_name TEXT NOT NULL,
  tea_id INTEGER NOT NULL,
  note TEXT,
  total REAL NOT NULL,
  is_processed BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO teas (name, description, price) VALUES 
('Phantom Green', 'A mysterious blend that appears to shift colors in the moonlight. Said to enhance perception and reveal hidden truths.', 12.50),
('Digital Dragon Well', 'Ancient leaves processed through quantum encryption. Each sip unlocks new neural pathways.', 15.75),
('Binary Blossom', 'Delicate flowers that bloom only in data streams. Perfect for late-night coding sessions.', 18.25),
('Cyber Sencha', 'Enhanced with nootropics and digital essence. Boosts cognitive function by 42%.', 14.00),
('Neon Oolong', 'Glows with artificial bioluminescence. Popular among night hackers and digital nomads.', 16.50),
('Matrix Matcha', 'Powdered reality suspension. Warning: May cause temporary glimpses into alternate dimensions.', 22.00);
