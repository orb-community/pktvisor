#!/bin/bash
set -e

export PATH=$PATH:/usr/local/bin/:/usr/local/sbin/

# Add sleep to allow tty to be ready for Docker when using -it
if [ "$1" = 'pktvisor' ]; then
    sleep 1
fi

exec "$@"