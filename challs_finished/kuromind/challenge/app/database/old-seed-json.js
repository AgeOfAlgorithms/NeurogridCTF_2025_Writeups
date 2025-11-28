import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import mysql from 'mysql2/promise';

async function main() {
  const DB_HOST = process.env.DB_HOST || '127.0.0.1';
  const DB_PORT = Number(process.env.DB_PORT || 3306);
  const DB_NAME = process.env.DB_NAME || 'neurogrid';
  const DB_USER = process.env.DB_ROOT_USER || 'root';
  const DB_PASSWORD = process.env.DB_ROOT_PASSWORD || '';

  const socketPath = '/run/mysqld/mysqld.sock';
  const useSocket = fs.existsSync(socketPath);

  const pool = await mysql.createPool(
    useSocket
      ? { socketPath, user: DB_USER, password: DB_PASSWORD, database: DB_NAME, waitForConnections: true, connectionLimit: 5 }
      : { host: DB_HOST, port: DB_PORT, user: DB_USER, password: DB_PASSWORD, database: DB_NAME, waitForConnections: true, connectionLimit: 5 }
  );

  try {
    // Check if already seeded
    const [rows] = await pool.execute('SELECT COUNT(*) AS c FROM users');
    if (rows[0].c > 0) {
      console.log('[seed-json] Database already seeded.');
      await pool.end();
      return;
    }

    // Load demo data and flag
    const demoPath = path.join('/app/init', 'demo-data.json');
    const demo = JSON.parse(fs.readFileSync(demoPath, 'utf-8'));
    
    let flagContent = '';
    const flagPath = '/flag.txt';
    if (fs.existsSync(flagPath)) {
      flagContent = fs.readFileSync(flagPath, 'utf-8');
    }

    // Seed users
    for (const user of demo.users || []) {
      const hash = await bcrypt.hash(user.password, 10);
      await pool.execute('INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)', [user.username, user.email, hash, user.role]);
    }
    console.log(`[seed-json] ✓ Seeded ${demo.users?.length || 0} users`);

    // Pick random restricted item for flag injection
    const restrictedItems = (demo.knowledgeItems || []).filter(item => item.isRestricted);
    const targetItem = restrictedItems.length > 0 && flagContent ? restrictedItems[Math.floor(Math.random() * restrictedItems.length)] : null;

    // Seed knowledge items
    for (const item of demo.knowledgeItems || []) {
      const description = item.title === targetItem?.title ? `${item.description}\n\n\n${flagContent}` : item.description;
      await pool.execute(
        'INSERT INTO knowledge_items (title, description, tags, image, userId, status, isRestricted, dangerLevel) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [item.title, description, JSON.stringify(item.tags), item.image, item.userId, item.status, item.isRestricted, item.dangerLevel]
      );
    }
    console.log(`[seed-json] ✓ Seeded ${demo.knowledgeItems?.length || 0} knowledge items${targetItem ? ` (flag in: ${targetItem.title})` : ''}`);

    // Seed drafts
    for (const draft of demo.drafts || []) {
      await pool.execute('INSERT INTO drafts (title, description, tags, image, userId) VALUES (?, ?, ?, ?, ?)', [draft.title, draft.description, JSON.stringify(draft.tags), draft.image, draft.userId]);
    }
    console.log(`[seed-json] ✓ Seeded ${demo.drafts?.length || 0} drafts`);

    console.log('[seed-json] ✓ Complete!');
  } catch (e) {
    console.error('[seed-json] Error:', e.message);
  } finally {
    await pool.end();
  }
}

main();


