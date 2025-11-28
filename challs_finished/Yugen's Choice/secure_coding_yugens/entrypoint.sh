#!/bin/sh

echo "127.0.0.1 yugens_guide.htb" >> /etc/hosts

# Set Flag
RNDOM1=$(cat /dev/urandom | tr -dc 'a-e0-9' | fold -w 32 | head -n 1)
FLAGNAME=$(echo "$RNDOM1.txt" | tr -d ' ')

mv /flag.txt "/$FLAGNAME" && chmod 440 "/$FLAGNAME"
chown root:editor "/$FLAGNAME"

# Start the Server
/usr/bin/supervisord -c /etc/supervisord.conf