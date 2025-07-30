#!/bin/sh
set -e

# Change ownership of the application directories to the 0x0 user
chown -R 0x0:0x0 /app/up /app/sqlite /app/socket

# Execute the provided command as the 0x0 user
exec su 0x0 "$@"
