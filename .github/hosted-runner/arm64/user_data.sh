#!/bin/sh

#installing packages
apt-get update -y
apt-get install apt-transport-https qemu qemu-user-static ca-certificates gnupg2 curl tar software-properties-common build-essential zlib1g-dev \
libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev libbz2-dev python3 python3-pip python3-dev python2 xvfb \
libfontconfig1 libfreetype6 xfonts-scalable fonts-liberation fonts-noto-cjk g++-10-arm-linux-gnueabihf cmake \
gcc-10-arm-linux-gnueabihf gcc-10-arm-linux-gnueabihf-base python3-venv tcpreplay docker.io containerd zip -y

#set permission to use docker
usermod -aG docker ubuntu

#creating directory git actions runner
mkdir actions-runner && cd actions-runner

chown ubuntu.ubuntu /actions-runner -R

#get git actions self-runner
/bin/su -c "cd /actions-runner && curl -o actions-runner-linux-arm64-2.294.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.294.0/actions-runner-linux-arm64-2.294.0.tar.gz" - ubuntu >> /home/ubuntu/user-data.log

#extract git actions runner installer
/bin/su -c "cd /actions-runner && tar xzf ./actions-runner-linux-arm64-2.294.0.tar.gz" - ubuntu >> /home/ubuntu/user-data.log

/bin/su -c "cd /actions-runner && ./config.sh --unattended --url https://github.com/ns1labs/pktvisor --token RUNNER_TOKEN --name ARM64_RUNNER --labels RUNNER_LABEL --work _work --runasservice" - ubuntu >> /home/ubuntu/user-data.log

/bin/su -c "cd /actions-runner && ./run.sh" - ubuntu >> /home/ubuntu/user-data.log
