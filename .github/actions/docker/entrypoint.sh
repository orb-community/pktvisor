#!/bin/sh -l

function build() {
  echo "========================= Building pktvisor ========================="
  cp -rf ${INPUT_WORKSPACE}/.git/ /pktvisor-src/.git/
  cp -rf ${INPUT_WORKSPACE}/src/ /pktvisor-src/src/
  cp -rf ${INPUT_WORKSPACE}/cmd/ /pktvisor-src/cmd/
  cp -rf ${INPUT_WORKSPACE}/3rd/ /pktvisor-src/3rd/
  cp -rf ${INPUT_WORKSPACE}/docker/ /pktvisor-src/docker/
  cp -rf ${INPUT_WORKSPACE}/golang/ /pktvisor-src/golang/
  cp -rf ${INPUT_WORKSPACE}/integration_tests/ /pktvisor-src/integration_tests/
  cp -rf ${INPUT_WORKSPACE}/cmake/ /pktvisor-src/cmake/
  cp -rf ${INPUT_WORKSPACE}/CMakeLists.txt /pktvisor-src/
  cp -rf ${INPUT_WORKSPACE}/conanfile.txt /pktvisor-src/
  mkdir /tmp/build
  cp /tmp/build
  conan profile new --detect default && \
  conan profile update settings.compiler.libcxx=libstdc++11 default && \
  conan config set general.revisions_enabled=1
  PKG_CONFIG_PATH=/local/lib/pkgconfig cmake -DCMAKE_BUILD_TYPE=Debug -DASAN=ON /pktvisor-src && \
  make all -j 4

}

function publish() {
  echo "========================= Publishing to backtrace ========================="
  zip pktvisord.zip /tmp/build/bin/pktvisord
  curl --data-binary @pktvisord.zip -H "Expect: gzip" "https://pktvisortest.sp.backtrace.io:6098/post?format=symbols&token=b109dbe0fb5fe46c83de7b11ca5d47eb122a6803461fe277850b89eac153eac0"

}

build

