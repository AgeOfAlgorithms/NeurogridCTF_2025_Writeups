#!/usr/bin/env bash
set -euo pipefail

echo "[init] Starting container initialization..."

# Ensure runtime dirs
mkdir -p /run/mysqld /var/lib/mysql
chown -R mysql:mysql /run/mysqld /var/lib/mysql

# Initialize MariaDB data directory if empty
if [ ! -d "/var/lib/mysql/mysql" ]; then
  echo "[init] Initializing MariaDB data directory..."
  mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null
fi

echo "[init] Starting supervisord..."
exec /usr/bin/supervisord -c /etc/supervisord.conf


