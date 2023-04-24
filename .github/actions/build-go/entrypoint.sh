#!/bin/bash
#
function build() {
  echo "========================= Building pktvisor-cli ========================="
  cp -rf golang/ /src/
  # Copying this from previous build (cpp)
  cp -rf ./version.go /src/pkg/client/version.go
  cd /src
  GOOS=$INPUT_GOOS GOARCH=$INPUT_GOARCH go build -o pktvisor-cli cmd/pktvisor-cli/main.go
}

function copy() {
  echo "========================= Copying binary ========================="
  cp -rf /src/pktvisor-cli /github/workspace/
}

build
copy
