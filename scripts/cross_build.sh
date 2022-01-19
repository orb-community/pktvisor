#!/bin/bash

CONAN=/root/venv/conan/bin/conan
SRC_DIR=/mnt/src
BUILD_PROFILE=default
HOST_PROFILE=host

set -ex

# workaround: build bison first because it fails when built as a build_requirement (for whatever reason)
"$CONAN" install -pr:b "$BUILD_PROFILE" -pr:h "$BUILD_PROFILE" --build=missing bison/3.7.1@

"$CONAN" install -pr:b "$BUILD_PROFILE" -pr:h "$HOST_PROFILE" --build=missing -g virtualenv "$SRC_DIR"
source environment.sh.env
export CC CXX
export LDFLAGS=-static

cmake "$SRC_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DPKTVISOR_CONAN_INIT=OFF -DPKTVISOR_CONAN_BUILD_PROFILE="$BUILD_PROFILE" -DPKTVISOR_CONAN_HOST_PROFILE="$HOST_PROFILE" \
    -DProtobuf_PROTOC_EXECUTABLE=$(command -v protoc) \
    -DCORRADE_RC_PROGRAM=$(command -v corrade-rc)

make -k -j4 VERBOSE=1
