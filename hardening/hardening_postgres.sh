#!/bin/bash

# Path to PostgreSQL config
PG_CONF="/var/lib/pgsql/data/postgresql.conf"

echo "Applying CIS Hardening..."

# 1. password_encryption = scram-sha-256
sed -i "s/^#\?password_encryption.*/password_encryption = 'scram-sha-256'/" $PG_CONF

# 2. listen_addresses (restrict access, adjust IP)
sed -i "s/^#\?listen_addresses.*/listen_addresses = 'localhost'/" $PG_CONF

# 3. log_connections = on
sed -i "s/^#\?log_connections.*/log_connections = on/" $PG_CONF

# 4. log_disconnections = on
sed -i "s/^#\?log_disconnections.*/log_disconnections = on/" $PG_CONF

# 5. log_min_error_statement = error
sed -i "s/^#\?log_min_error_statement.*/log_min_error_statement = error/" $PG_CONF

echo "Restarting PostgreSQL..."
systemctl restart postgresql

echo "Config hardening applied."