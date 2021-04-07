#!/usr/bin/env bash

exec agent --config.file=/etc/agent/agent.yaml --prometheus.wal-directory=/etc/agent/data
