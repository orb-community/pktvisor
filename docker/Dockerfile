FROM debian:bullseye-slim AS cppbuild

ENV BUILD_DEPS "g++ cmake make git pkgconf jq python3-pip python3-setuptools ca-certificates"

RUN \
    apt-get update && \
    apt-get upgrade --yes --force-yes && \
    apt-get install --yes --force-yes --no-install-recommends ${BUILD_DEPS} && \
    pip3 install conan

COPY . /pktvisor-src/

WORKDIR /tmp/build
RUN \
    conan profile new --detect default && \
    conan profile update settings.compiler.libcxx=libstdc++11 default && \
    conan config set general.revisions_enabled=1

RUN \
    PKG_CONFIG_PATH=/local/lib/pkgconfig cmake -DCMAKE_BUILD_TYPE=Release /pktvisor-src && \
    make all test -j 4

FROM golang:latest AS gobuild
COPY golang/ /src/
WORKDIR /src/
COPY --from=cppbuild /pktvisor-src/golang/pkg/client/version.go /src/pkg/client/version.go
RUN go build -o pktvisor-cli cmd/pktvisor-cli/main.go

FROM debian:bullseye-slim AS runtime

ENV RUNTIME_DEPS "curl ca-certificates"

RUN \
    apt-get update && \
    apt-get upgrade --yes --force-yes && \
    apt-get install --yes --force-yes --no-install-recommends ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt

COPY --from=cppbuild /tmp/build/bin/pktvisord /usr/local/sbin/pktvisord
COPY --from=cppbuild /tmp/build/bin/pktvisor-pcap /usr/local/sbin/pktvisor-pcap
COPY --from=gobuild /src/pktvisor-cli /usr/local/bin/pktvisor-cli
COPY docker/entry.sh /usr/local/bin/

ENTRYPOINT [ "entry.sh" ]

