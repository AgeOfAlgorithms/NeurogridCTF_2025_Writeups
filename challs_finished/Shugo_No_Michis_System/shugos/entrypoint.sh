#!/bin/bash
set -euo pipefail

DATA_DIR="/var/lib/postgresql/data"
PGBIN="${PGBIN:-/usr/bin}"
BIN_DIR=$PGBIN

export PATH="$PGBIN:$PATH"


# Initialize the Database
if [ ! -s "$DATA_DIR/PG_VERSION" ]; then
  echo "[db] initializing cluster..."

  install -d -m 0700 -o postgres -g postgres "$DATA_DIR"
  su - postgres -c "$BIN_DIR/initdb -D $DATA_DIR --encoding=UTF8 --locale=C.UTF-8"

  # open listen + auth rules
  sed -ri "s/^[#\s]*listen_addresses\s*=.*/listen_addresses = '*'/" "$DATA_DIR/postgresql.conf"
  {
    echo "local   all   all                          peer"
    echo "host    all   all   127.0.0.1/32           md5"
    echo "host    all   all   ::1/128                md5"
    echo "host    all   all   0.0.0.0/0              md5"
  } >> "$DATA_DIR/pg_hba.conf"

  # start a temporary server without external bind for seeding
  su - postgres -c "$BIN_DIR/pg_ctl -D $DATA_DIR -o \"-c listen_addresses=''\" -w start"

  # set postgres role password so md5 works
  su - postgres -c "psql -d postgres -v ON_ERROR_STOP=1 -c \"ALTER USER postgres WITH PASSWORD 'postgres';\""

  # run schema with psql variable for seed password (default if unset)
  : "${SEED_PASSWORD:=SuperSecureAdminPassword}"
  su - postgres -c "psql -v seed_password='${SEED_PASSWORD}' -d postgres -f /app/core_app/database/schema.sql"

  # stop temp server
  su - postgres -c "$BIN_DIR/pg_ctl -D $DATA_DIR -m fast -w stop"
fi

export PGBIN="${PGBIN:-/usr/bin}" # For Supervisord



# Set Flag
set +o pipefail
RANDOM1=$(tr -dc 'a-e0-9' </dev/urandom | fold -w32 | head -n1 | tr -d '\r\n')
set -o pipefail

mv /flag.txt "/$RANDOM1.txt" && chmod 440 "/$RANDOM1.txt"
chown root:editor "/$RANDOM1.txt"

/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf