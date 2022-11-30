#!/bin/sh

#installing packages
dpkg --add-architecture armhf

apt-get update -y
apt-get install apt-transport-https curl -y

# add GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

RELEASE=$(lsb_release -c | cut -f2)

apt-get update -y
apt-get install qemu qemu-user-static ca-certificates gnupg2 curl tar software-properties-common build-essential zlib1g-dev \
libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev libbz2-dev python3 python3-pip python3-dev python2 xvfb \
libfontconfig1 libfreetype6 xfonts-scalable fonts-liberation fonts-noto-cjk g++-10-arm-linux-gnueabihf cmake openssl \
gcc-10-arm-linux-gnueabihf gcc-10-arm-linux-gnueabihf-base python3-venv tcpreplay docker.io containerd debhelper -y

# wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz
# tar zxf openssl-1.1.1k.tar.gz
# make
# make install
# ldconfig

# wget https://zlib.net/zlib-1.2.11.tar.gz
# tar xvf zlib-1.2.11.tar.gz
# ./configure
# make all install
# ldconfig

mkdir /etc/systemd/system/docker.service.d

(
cat <<END
[Service]
ExecStart=
ExecStart=/usr/bin/setarch linux32 -B /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
END
) > "/etc/systemd/system/docker.service.d/override.conf"

mkdir /etc/systemd/system/containerd.service.d

(
cat <<END
[Service]
ExecStart=
ExecStart=/usr/bin/setarch linux32 -B /usr/bin/containerd
END
) > "/etc/systemd/system/containerd.service.d/override.conf"

#set permission to use docker
usermod -aG docker ubuntu

# restart services
systemctl daemon-reload
systemctl restart docker

#creating directory git actions runner
mkdir actions-runner && cd actions-runner

chown ubuntu.ubuntu /actions-runner -R

#get git actions self-runner
/bin/su -c "cd /actions-runner && curl -o actions-runner-linux-arm64-2.294.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.294.0/actions-runner-linux-arm64-2.294.0.tar.gz" - ubuntu >> /home/ubuntu/user-data.log

#extract git actions runner installer
/bin/su -c "cd /actions-runner && tar xzf ./actions-runner-linux-arm64-2.294.0.tar.gz" - ubuntu >> /home/ubuntu/user-data.log

/bin/su -c "cd /actions-runner && ./config.sh --unattended --url https://github.com/ns1labs/pktvisor --token RUNNER_TOKEN --name ARM32_RUNNER --labels RUNNER_LABEL --work _work --runasservice" - ubuntu >> /home/ubuntu/user-data.log

/bin/su -c "cd /actions-runner && ./run.sh" - ubuntu >> /home/ubuntu/user-data.log
