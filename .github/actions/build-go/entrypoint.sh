#!/bin/bash
#

function build() {
  echo "========================= Building pktvisor-cli ========================="
  cp -rf golang/ /src/
  cp -rf ./version.go /src/pkg/client/version.go
  go mod tidy
  go build -o pktvisor-cli cmd/pktvisor-cli/main.go
  ls -lha
}

function copy() {
  echo "========================= Compacting binary and copying ========================="
  cp -rf /tmp/build/bin/pktvisor-cli /github/workspace/
}

build
#copy