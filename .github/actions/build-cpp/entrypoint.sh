#!/bin/bash
#
function validateParams() {
  echo "========================= Checking parameters ========================="
  [[ -z $INPUT_SYMBOL_URL ]] && echo "Backtrace symbol url is required" && exit 1 || echo "Backtrace symbol url present"
}

function build() {
  echo "========================= Building pktvisor ========================="
  cp -rf /github/workspace/.git/ /pktvisor-src/.git/
  cp -rf /github/workspace/src/ /pktvisor-src/src/
  cp -rf /github/workspace/cmd/ /pktvisor-src/cmd/
  cp -rf /github/workspace/3rd/ /pktvisor-src/3rd/
  cp -rf /github/workspace/libs/ /pktvisor-src/libs/
  cp -rf /github/workspace/docker/ /pktvisor-src/docker/
  cp -rf /github/workspace/golang/ /pktvisor-src/golang/
  cp -rf /github/workspace/integration_tests/ /pktvisor-src/integration_tests/
  cp -rf /github/workspace/cmake/ /pktvisor-src/cmake/
  cp -rf /github/workspace/CMakeLists.txt /pktvisor-src/
  cp -rf /github/workspace/conanfile.txt /pktvisor-src/
  mkdir /tmp/build
  cd /tmp/build
  conan profile new --detect default
  conan profile update settings.compiler.libcxx=libstdc++11 default
  conan config set general.revisions_enabled=1
  PKG_CONFIG_PATH=/local/lib/pkgconfig cmake -DCMAKE_BUILD_TYPE=$INPUT_BUILD_TYPE -DASAN=$INPUT_ASAN /pktvisor-src
  make all -j 4
}

function compact() {
  echo "========================= Compacting binary and copying ========================="
  cd /tmp/build
  zip pktvisord.zip /tmp/build/bin/pktvisord
  cp -rf /tmp/build/bin/pktvisord /github/workspace/
  strip -s /tmp/build/bin/crashpad_handler
  cp -rf /tmp/build/bin/crashpad_handler /github/workspace/
  cp -rf /tmp/build/bin/pktvisor-reader /github/workspace/
  cp -rf /tmp/build/VERSION /github/workspace/
  #version for pktvisor-cli
  cp -rf /pktvisor-src/golang/pkg/client/version.go /github/workspace/version.go
  #copy pktvisor custom iana port service names file
  cp -rf /pktvisor-src/src/tests/fixtures/pktvisor-port-service-names.csv /github/workspace/custom-iana.csv
}

function publish() {
  echo "========================= Publishing symbol to backtrace ========================="
  cd /tmp/build
  curl --data-binary @pktvisord.zip -H "Expect: gzip" "${INPUT_SYMBOL_URL}"
}

function publishToBugsplat() {
  echo "========================= Publishing symbol to bugsplat ========================="
  cd /tmp/build
  curl --data-binary @pktvisord.zip -H "Expect: gzip" "${INPUT_SYMBOL_URL}"
}


validateParams
build
compact
publish
publishToBugsplat
