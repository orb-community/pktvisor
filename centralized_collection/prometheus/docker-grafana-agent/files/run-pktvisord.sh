#!/usr/bin/env bash

[[ "$PKTVISORD_ARGS" == "" ]] && PKTVISORD_ARGS="eth0"

# allow for space after semi ('; ') for better readability and strip leading spaces in args
PKTVISORD_ARGS="${PKTVISORD_ARGS//; /;}"
IFS=$';'
exec pktvisord --prometheus $PKTVISORD_ARGS
