FROM debian:buster-slim AS build

ENV BUILD_DEPS "g++ cmake make git libpcap-dev pkgconf golang ca-certificates libmaxminddb-dev jq python3-pip python3-setuptools"

RUN \
    apt-get update && \
    apt-get install --yes --no-install-recommends ${BUILD_DEPS}

RUN \
    pip3 install conan

COPY . /src

RUN \
    mkdir /local && \
    cd /tmp && \
    git clone https://github.com/ns1/PcapPlusPlus.git

RUN \
    cd /tmp/PcapPlusPlus && \
    ./configure-linux.sh --install-dir /local && \
    make libs && \
    make install

RUN \
    conan profile new --detect default && \
    conan profile update settings.compiler.libcxx=libstdc++11 default && \
    mkdir /tmp/build && \
    cd /tmp/build && \
    conan install /src && \
    PKG_CONFIG_PATH=/local/lib/pkgconfig cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo /src && \
    make all

RUN \
    cd /tmp/build && \
    go get github.com/pkg/errors && \
    go get github.com/jroimartin/gocui && \
    go get github.com/docopt/docopt-go && \
    cd /src/cmd/pktvisor && \
    go build

FROM debian:buster-slim AS runtime

ENV RUNTIME_DEPS "curl libpcap0.8 libmaxminddb0"

RUN \
    apt-get update && \
    apt-get install --yes --no-install-recommends ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt

COPY --from=build /tmp/build/bin/pktvisord /usr/local/sbin/pktvisord
COPY --from=build /tmp/build/bin/pktvisor-pcap /usr/local/sbin/pktvisor-pcap
COPY --from=build /src/golang/cmd/pktvisor-cli/pktvisor-cli /usr/local/bin/pktvisor-cli
COPY docker/entry.sh /usr/local/bin/

ENTRYPOINT [ "entry.sh" ]

