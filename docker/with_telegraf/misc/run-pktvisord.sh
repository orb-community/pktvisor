#!/usr/bin/env bash

[[ "$PKTVISORD_ARGS" == "" ]] && PKTVISORD_ARGS="eth0"

exec pktvisord $PKTVISORD_ARGS
