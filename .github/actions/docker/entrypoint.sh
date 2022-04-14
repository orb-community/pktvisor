#!/bin/sh -l

function validateParams() {
  echo "========================= Checking parameters ========================="
  [[ -z $INPUT_REGISTRY_TOKEN ]] && echo "Registry token is required" && exit 1 || echo "Registry token present"
  [[ -z $INPUT_NAME ]] && echo "Docker image name is required" && exit 1 || echo "Docker image name present"
}

function build() {
  echo "========================= Building pktvisor ========================="
  mkdir /pktvisor-src/
  cp -rf ${INPUT_CONTEXT}/.git/ /pktvisor-src/.git/
  cp -rf ${INPUT_CONTEXT}/src/ /pktvisor-src/src/
  cp -rf ${INPUT_CONTEXT}/cmd/ /pktvisor-src/cmd/
  cp -rf ${INPUT_CONTEXT}/3rd/ /pktvisor-src/3rd/
  cp -rf ${INPUT_CONTEXT}/docker/ /pktvisor-src/docker/
  cp -rf ${INPUT_CONTEXT}/golang/ /pktvisor-src/golang/
  cp -rf ${INPUT_CONTEXT}/integration_tests/ /pktvisor-src/integration_tests/
  cp -rf ${INPUT_CONTEXT}/cmake/ /pktvisor-src/cmake/
  cp -rf ${INPUT_CONTEXT}/CMakeLists.txt /pktvisor-src/
  cp -rf ${INPUT_CONTEXT}/conanfile.txt /pktvisor-src/
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

