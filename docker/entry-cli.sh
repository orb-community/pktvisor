#!/bin/sh
# this is the entry point to the docker container, and is only used there
set -e
export PATH=$PATH:/usr/local/bin/:/usr/local/sbin/

# Add sleep to allow tty to be ready for Docker when using -it
echo "starting pktvisor-cli..."
sleep 1

exec /pktvisor-cli
