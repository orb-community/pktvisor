#!/usr/bin/env bash

[[ "$PKTVISOR_ARGS" == "" ]] && PKTVISOR_ARGS="eth0"

exec pktvisord --prometheus $PKTVISOR_ARGS
