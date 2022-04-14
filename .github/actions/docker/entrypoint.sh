#!/bin/sh -l

function validateParams() {
  echo "========================= Checking parameters ========================="
  [[ -z $INPUT_REGISTRY_TOKEN ]] && echo "Registry token is required" && exit 1 || echo "Registry token present"
  [[ -z $INPUT_NAME ]] && echo "Docker image name is required" && exit 1 || echo "Docker image name present"
  [[ -z $INPUT_REGISTRY ]] && echo "Registry url is required" && exit 1 || echo "Registry url present"
  [[ -z $INPUT_TAG ]] && echo "Docker image tag is required" && exit 1 || echo "Docker tag token present"
  [[ -z $INPUT_USER ]] && echo "Registry user is required" && exit 1 || echo "Registry user present"
  # [[ -z $INPUT_TOKEN ]] && echo "Token is required" && exit 1 echo "Token present"
  
}

function setup() {
  echo "========================= Set Docker environment ========================="
  export GITHUB_PR_ISSUE_NUMBER=$(jq --raw-output .pull_request.number "$GITHUB_EVENT_PATH")

  validateParams
  echo $INPUT_REGISTRY_TOKEN > DOCKER_TOKEN.txt
  echo "docker login ${INPUT_REGISTRY} --username ${INPUT_USER} --password-stdin"
  cat ./DOCKER_TOKEN.txt | docker login $INPUT_REGISTRY --username $INPUT_USER --password-stdin
}

function build() {
  echo "========================= Building pktvisor ========================="

  conan profile new --detect default && \
  conan profile update settings.compiler.libcxx=libstdc++11 default && \
  conan config set general.revisions_enabled=1

  PKG_CONFIG_PATH=/local/lib/pkgconfig cmake -DCMAKE_BUILD_TYPE=Debug -DASAN=ON /pktvisor-src && \
  make all -j 4

}

function publish() {
  if [ $INPUT_PUSH != "false" ];
  then
    echo "========================= Publishing to backtrace ========================="
    curl --data-binary @pktvisord.zip -H "Expect: gzip" "https://pktvisortest.sp.backtrace.io:6098/post?format=symbols&token=b109dbe0fb5fe46c83de7b11ca5d47eb122a6803461fe277850b89eac153eac0"
  else
    echo "Docker publish skipped"
  fi
}


setup
run
test
publish
clean
