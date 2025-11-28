#!/bin/sh

# Generate random string
generate_random() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $1 | head -n 1
}

# Create .env if it doesn't exist
if [ ! -f "/app/.env" ]; then
    DB_PASSWORD=$(generate_random 32)
    SESSION_SECRET=$(generate_random 64)
    OPERATOR_SECRET=$(generate_random 64)
    EMAIL_SECRET=$(generate_random 64)
    
    cat > /app/.env << EOF
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=neurogrid_user
DB_PASSWORD=$DB_PASSWORD
DB_NAME=neurogrid
SESSION_SECRET=$SESSION_SECRET
NODE_ENV=production
EOF
    
    chmod 600 /app/.env
    echo "✅ .env generated"
fi
