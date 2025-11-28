#!/bin/bash
set -euo pipefail

# Load .env if it exists
if [ -f "/app/.env" ]; then
  export $(cat /app/.env | grep -v '^#' | xargs)
fi

# Use values from .env or fallback to defaults
DB_HOST="${DB_HOST:=127.0.0.1}"
DB_PORT="${DB_PORT:=3306}"
DB_NAME="${DB_NAME:=neurogrid}"
DB_USER="${DB_USER:=neurogrid_user}"
DB_PASSWORD="${DB_PASSWORD:=neurogrid_password_change_me}"

echo "[init_db] Starting database initialization..."
echo "[init_db] Using DB_PASSWORD from .env"

# Wait for MySQL to be ready (via TCP this time)
for i in {1..60}; do
  if mysqladmin -h "$DB_HOST" -P "$DB_PORT" -uroot ping >/dev/null 2>&1; then
    echo "[init_db] ✓ MySQL is ready!"
    break
  fi
  echo "[init_db] Waiting for MySQL... (attempt $i/60)"
  sleep 1
done

if ! mysqladmin -h "$DB_HOST" -P "$DB_PORT" -uroot ping >/dev/null 2>&1; then
  echo "[init_db] ERROR: MariaDB did not become ready in time" >&2
  exit 1
fi

# Add extra delay to ensure authentication is fully initialized
sleep 2

echo "[init_db] Ensuring database and user exist..."
mysql --protocol=socket --socket=/run/mysqld/mysqld.sock -uroot <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'127.0.0.1';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'%';
FLUSH PRIVILEGES;
SQL

if [ -f "/app/init/init.sql" ]; then
  echo "[init_db] Applying schema from /app/init/init.sql..."
  mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < /app/init/init.sql || true
fi

if [ -f "/app/init/demo-data.json" ]; then
  echo "[init_db] Seeding demo-data.json..."
  export DB_ROOT_USER=root
  export DB_ROOT_PASSWORD=""
  node /app/init/seed-json.js || true
fi

echo "[init_db] ✓ Database initialization complete!"
exit 0
