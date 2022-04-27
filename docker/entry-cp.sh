#!/bin/bash
# this is the entry point to the docker container, and is only used there
set -e

export PATH=$PATH:/usr/local/bin/:/usr/local/sbin/

if [ $# -eq 0 ]; then
  echo "No arguments provided: specify either 'pktvisor-cli', 'pktvisor-reader' or 'pktvisord'. Try:"
  echo "docker run ns1labs/pktvisor pktvisor-cli -h"
  echo "docker run ns1labs/pktvisor pktvisor-reader --help"
  echo "docker run ns1labs/pktvisor pktvisord --help"
  exit 1
fi

# backwards compatibility
BINARY="$1"
if [ "$BINARY" = 'pktvisor' ]; then
  BINARY='pktvisor-cli'
fi

if [ "$BINARY" = 'pktvisor-pcap' ]; then
  BINARY='pktvisor-reader'
fi

# Add sleep to allow tty to be ready for Docker when using -it
if [ "$BINARY" = 'pktvisor-cli' ]; then
  sleep 1
fi

# if binary is pktvisord
if [ "$BINARY" = 'pktvisord' ]; then
  shift
  exec "$BINARY" --cp-token "CP_TOKEN" --cp-url "CP_URL" --cp-path "/usr/local/sbin/crashpad_handler" "$@"
  sleep 5
else
  shift
  exec "$BINARY" "$@"
fi
