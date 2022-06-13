#!/bin/sh
#scaling privileges
sudo su

#installing packages
apt-get update -y
apt-get install apt-transport-https ca-certificates gnupg2 curl tar software-properties-common build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev libbz2-dev python3 python3-pip python3-dev python xvfb libfontconfig1 libfreetype6 xfonts-scalable fonts-liberation fonts-noto-cjk -y

#install docker
apt-get update -y
apt-get install docker.io containerd -y

#creating directory git actions runner
mkdir actions-runner && cd actions-runner

#python stuffs
pip3 install --no-cache-dir requests unittest-xml-reporting nose mockito pyshould

pip3 install --no-cache-dir \
        behave==1.2.6 \
        behavex==1.5.4  \
        selenium==4.1.3 \
        docker \
        PyHamcrest \
        PyYAML \
        retry==0.9.2 \
        deepdiff \
        jsonschema==4.6.0 \
        mkdocs \
        mkdocs-material \
        capybara-py             \
        xvfbwrapper

pip3 install --upgrade requests

#get git actions self-runner
curl -o actions-runner-linux-arm64-2.292.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.292.0/actions-runner-linux-arm64-2.292.0.tar.gz

#extract git actions runner installer
tar xzf ./actions-runner-linux-arm64-2.292.0.tar.gz

RUNNER_ALLOW_RUNASROOT="1" ./config.sh --url https://github.com/etaques/pktvisor --token RUNNER_TOKEN --name arm64_runner --work _work --runasservice

RUNNER_ALLOW_RUNASROOT="1" ./run.sh
