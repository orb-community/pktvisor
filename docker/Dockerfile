FROM debian:bullseye-slim AS conanbuild

ARG TARGETOS
ARG TARGETARCH
ARG TARGETPLATFORM

ENV BUILD_DEPS "g++ clang cmake make git pkgconf jq python3-pip python3-setuptools ca-certificates python python3"

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ${BUILD_DEPS} && \
    pip3 install conan

# need git for current hash for VERSION
COPY ./.git/ /pktvisor-src/.git/
COPY ./src/ /pktvisor-src/src/
COPY ./cmd/ /pktvisor-src/cmd/
COPY ./3rd/ /pktvisor-src/3rd/
COPY ./docker/ /pktvisor-src/docker/
COPY ./golang/ /pktvisor-src/golang/
COPY ./integration_tests/ /pktvisor-src/integration_tests/
COPY ./cmake/ /pktvisor-src/cmake/
COPY ./CMakeLists.txt /pktvisor-src/
COPY ./conanfile.txt /pktvisor-src/

WORKDIR /tmp/build
RUN \
    conan profile new --detect default && \
    conan profile update settings.compiler.libcxx=libstdc++10 default && \
    conan config set general.revisions_enabled=1

FROM --platform=$BUILDPLATFORM tonistiigi/xx AS xx

FROM --platform=$BUILDPLATFORM debian:bullseye AS cppbuild
# copy xx scripts to your build stage
COPY --from=xx / /

ARG TARGETOS
ARG TARGETARCH
ARG TARGETPLATFORM

ENV BUILD_DEPS "cmake clang make lld"

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ${BUILD_DEPS}

RUN xx-apt-get update && \
    xx-apt-get install -y musl-dev gcc g++ libstdc++-10-dev

# getting project files
COPY --from=conanbuild /pktvisor-src/ /pktvisor-src/

# getting conan files
COPY --from=conanbuild /tmp/build/ /tmp/build/

WORKDIR /tmp/build

RUN xx-info env
# run make
RUN cmake $(xx-clang++ --print-cmake-defines) -DCMAKE_BUILD_TYPE=Release /pktvisor-src
RUN make all

FROM --platform=$BUILDPLATFORM golang:latest AS gobuild
ARG TARGETOS
ARG TARGETARCH
ARG TARGETPLATFORM

COPY golang/ /src/
WORKDIR /src/
COPY --from=cppbuild /pktvisor-src/golang/pkg/client/version.go /src/pkg/client/version.go
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o pktvisor-cli cmd/pktvisor-cli/main.go

FROM --platform=$BUILDPLATFORM debian:bullseye-slim AS binary_publisher
ARG ghtoken
ARG TARGETOS
ARG TARGETARCH
ARG TARGETPLATFORM

ENV RUNTIME_DEPS "curl ca-certificates"

RUN \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ${RUNTIME_DEPS}

COPY --from=cppbuild /tmp/build/bin/pktvisord /usr/local/sbin/pktvisord
COPY --from=cppbuild /tmp/build/bin/pktvisor-reader /usr/local/sbin/pktvisor-reader
COPY --from=gobuild /src/pktvisor-cli /usr/local/bin/pktvisor-cli
COPY docker/upload-gh-asset.sh /upload-gh-asset.sh
RUN chmod a+x /upload-gh-asset.sh

#zip binaries
RUN tar -czvf "pktvisor-${TARGETARCH}.tar.gz"  /usr/local/sbin/pktvisord /usr/local/sbin/pktvisor-reader /usr/local/bin/pktvisor-cli

#push asset to release assets
RUN /upload-gh-asset.sh github_api_token=${ghtoken} owner=ns1labs repo=pktvisor tag=LATEST filename=pktvisor-${TARGETARCH}.tar.gz

FROM debian:bullseye-slim

ENV RUNTIME_DEPS "curl ca-certificates"

RUN \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt

COPY --from=cppbuild /tmp/build/bin/pktvisord /usr/local/sbin/pktvisord
COPY --from=cppbuild /tmp/build/bin/pktvisor-reader /usr/local/sbin/pktvisor-reader
COPY --from=gobuild /src/pktvisor-cli /usr/local/bin/pktvisor-cli
COPY docker/entry.sh /entry.sh
RUN chmod a+x /entry.sh

ENTRYPOINT [ "/entry.sh" ]

