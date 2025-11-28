#!/bin/sh

echo "127.0.0.1 odayaka.htb" >> /etc/hosts

RNDOM1=$(cat /dev/urandom | tr -dc 'a-e0-9' | fold -w 32 | head -n 1)
FLAGNAME=$(echo "$RNDOM1.txt" | tr -d ' ')

chown root:editor /flag.txt
mv /flag.txt "/$FLAGNAME" && chmod 440 "/$FLAGNAME"

# Start supervisord which will manage all services
/usr/bin/supervisord -c /etc/supervisord.conf