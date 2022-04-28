#!/bin/bash
shift
pktvisord --cp-token "CP_TOKEN" --cp-url "CP_URL" --cp-path "/usr/local/sbin/crashpad_handler" "$@" &
echo $! > /var/run/pktvisord.pid