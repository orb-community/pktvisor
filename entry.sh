#!/bin/bash
# this is the entry point to the docker container, and is only used there
set -e

export PATH=$PATH:/usr/local/bin/:/usr/local/sbin/

if [ $# -eq 0 ]; then
    echo "No arguments provided: specify either 'pktvisor' or 'pktvisord'. Try:"
    echo "docker run ns1labs/pktvisor pktvisor --help"
    echo "docker run ns1labs/pktvisor pktvisord --help"
    exit 1
fi

# Add sleep to allow tty to be ready for Docker when using -it
if [ "$1" = 'pktvisor' ]; then
    sleep 1
fi

exec "$@"