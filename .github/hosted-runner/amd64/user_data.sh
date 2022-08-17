#!/bin/sh
# scaling privileges
sudo su

#installing packages
apt-get update -y
apt-get install apt-transport-https qemu qemu-user-static ca-certificates gnupg2 curl tar software-properties-common build-essential zlib1g-dev \
libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev libbz2-dev python3 python3-pip python3-dev python xvfb \
libfontconfig1 libfreetype6 xfonts-scalable fonts-liberation fonts-noto-cjk g++-10-arm-linux-gnueabihf g++-10-multilib-arm-linux-gnueabihf \
gcc-10-arm-linux-gnueabihf gcc-10-arm-linux-gnueabihf-base gcc-10-multilib-arm-linux-gnueabihf python3-venv tcpreplay -y

#install docker
apt-get update -y
apt-get install docker.io containerd -y

#creating directory git actions runner
mkdir actions-runner && cd actions-runner

#get git actions self-runner
curl -o actions-runner-linux-x64-2.294.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.294.0/actions-runner-linux-x64-2.294.0.tar.gz

#extract git actions runner installer
tar xzf ./actions-runner-linux-x64-2.294.0.tar.gz

RUNNER_ALLOW_RUNASROOT="1" ./config.sh --url https://github.com/ns1labs/pktvisor --token RUNNER_TOKEN --name amd64_runner --work _work --runasservice

RUNNER_ALLOW_RUNASROOT="1" ./run.sh
