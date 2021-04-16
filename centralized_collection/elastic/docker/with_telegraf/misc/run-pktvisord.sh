#!/usr/bin/env bash

[[ "$VIZERD_ARGS" == "" ]] && VIZERD_ARGS="eth0"

exec pktvisord $VIZERD_ARGS
