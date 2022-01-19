FROM debian:unstable-20211220-slim AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends git make cmake gcc g++ python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /root/venv/conan \
    && /root/venv/conan/bin/pip install --no-cache-dir conan

ENV PATH="/root/venv/conan/bin:${PATH}"

RUN conan config set general.revisions_enabled=1 \
    && CONAN_V2_MODE=1 conan profile new --detect default \
    && conan remote add ns1labs https://ns1labs.jfrog.io/artifactory/api/conan/ns1labs-conan

FROM base AS x86_64

# https://musl.cc/x86_64-linux-musl-cross.tgz
ADD x86_64-linux-musl-cross.tgz /opt/

# we always need to link staticaly because the build system doesn't recognize this is a cross-compilation
RUN cp /root/.conan/profiles/default /root/.conan/profiles/host \
    && conan profile update options.pcapplusplus:with_musl=True host \
    && conan profile update env.CC=/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc host \
    && conan profile update env.CXX=/opt/x86_64-linux-musl-cross/bin/x86_64-linux-musl-g++ host \
    && conan profile update env.LDFLAGS=-static host

FROM base AS armv7l

# http://musl.cc/armv7l-linux-musleabihf-cross.tgz
ADD armv7l-linux-musleabihf-cross.tgz /opt/
RUN cp /root/.conan/profiles/default /root/.conan/profiles/host \
    && conan profile update settings.arch=armv7hf host \
    && conan profile update options.pcapplusplus:with_musl=True host \
    && conan profile update env.CC=/opt/armv7l-linux-musleabihf-cross/bin/armv7l-linux-musleabihf-gcc host \
    && conan profile update env.CXX=/opt/armv7l-linux-musleabihf-cross/bin/armv7l-linux-musleabihf-g++ host

FROM base AS aarch64

# http://musl.cc/armv7l-linux-musleabihf-cross.tgz
ADD aarch64-linux-musl-cross.tgz /opt/
RUN cp /root/.conan/profiles/default /root/.conan/profiles/host \
    && conan profile update settings.arch=armv8 host \
    && conan profile update options.pcapplusplus:with_musl=True host \
    && conan profile update env.CC=/opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc host \
    && conan profile update env.CXX=/opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-g++ host
