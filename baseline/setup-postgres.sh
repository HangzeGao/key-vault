#!/usr/bin/env bash
# setup-postgres.sh — Initialize PostgreSQL for the KVLT engineering baseline.
# Creates the kvlt user and database, then verifies connectivity.
# Run this once before starting the service with KVLT_DB_DRIVER=postgres.
set -euo pipefail

PG_USER="${PG_USER:-kvlt}"
PG_PASS="${PG_PASS:-secret}"
PG_DB="${PG_DB:-kvlt}"
PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-5432}"

# psql -h 127.0.0.1 -p 5432 -U kvlt -d kvlt -c "SHOW all;"

echo "=== KVLT PostgreSQL Setup ==="
echo "user: $PG_USER | db: $PG_DB | host: $PG_HOST:$PG_PORT"

# 1. Detect PostgreSQL installation.
if ! command -v psql >/dev/null 2>&1; then
  echo "ERROR: psql not found. Install PostgreSQL first:"
  echo "  Debian/Ubuntu:  sudo apt-get install -y postgresql postgresql-contrib"
  echo "  RHEL/CentOS:    sudo dnf install -y postgresql-server postgresql-contrib"
  echo "  Then initialize and start the service:"
  echo "    sudo postgresql-setup --initdb"
  echo "    sudo systemctl enable --now postgresql"
  exit 1
fi

# 2. Ensure the service is running.
if ! pg_isready -h "$PG_HOST" -p "$PG_PORT" >/dev/null 2>&1; then
  echo "PostgreSQL is not running on $PG_HOST:$PG_PORT. Attempting to start..."
  if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl start postgresql || true
  elif command -v service >/dev/null 2>&1; then
    sudo service postgresql start || true
  else
    echo "ERROR: cannot start PostgreSQL automatically. Start it manually:"
    echo "  sudo systemctl start postgresql"
    exit 1
  fi
  sleep 1
  if ! pg_isready -h "$PG_HOST" -p "$PG_PORT" >/dev/null 2>&1; then
    echo "ERROR: PostgreSQL still not reachable on $PG_HOST:$PG_PORT"
    echo "Check status: sudo systemctl status postgresql"
    exit 1
  fi
fi
echo "PostgreSQL is running."

# 3. Create user and database (idempotent).
#    Use sudo to access the postgres superuser.
echo "Creating role $PG_USER (if not exists)..."
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$PG_USER') THEN
    CREATE ROLE $PG_USER LOGIN PASSWORD '$PG_PASS';
    RAISE NOTICE 'Created role $PG_USER';
  ELSE
    RAISE NOTICE 'Role $PG_USER already exists';
  END IF;
END
\$\$;
SQL

echo "Creating database $PG_DB (if not exists)..."
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
SELECT 'CREATE DATABASE $PG_DB OWNER $PG_USER'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '$PG_DB')\gexec
GRANT ALL PRIVILEGES ON DATABASE $PG_DB TO $PG_USER;
SQL

# 4. Verify the kvlt user can connect.
echo "Verifying connection as $PG_USER..."
if PGPASSWORD="$PG_PASS" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" -c "SELECT version();" >/dev/null 2>&1; then
  echo "OK: $PG_USER can connect to $PG_DB"
else
  echo "ERROR: $PG_USER cannot connect to $PG_DB."
  echo "If pg_hba.conf requires md5/scram-sha-256, ensure the DSN uses the right auth."
  echo "DSN: postgres://$PG_USER:$PG_PASS@$PG_HOST:$PG_PORT/$PG_DB?sslmode=disable"
  exit 1
fi

# 5. Print the DSN to export.
echo ""
echo "=== Setup complete ==="
echo "Export these before running start.sh:"
echo "  export KVLT_DB_DRIVER=postgres"
echo "  export KVLT_DB_DSN='postgres://$PG_USER:$PG_PASS@$PG_HOST:$PG_PORT/$PG_DB?sslmode=disable'"
