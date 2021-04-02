#!/usr/bin/env bash

[[ "$PKTVISORD_ARGS" == "" ]] && PKTVISORD_ARGS="eth0"

exec pktvisord --prometheus $PKTVISORD_ARGS
