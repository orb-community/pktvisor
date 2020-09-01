FROM debian:buster-slim AS build

ENV BUILD_DEPS "g++ cmake make git libpcap-dev pkgconf golang ca-certificates libmaxminddb-dev jq"

RUN \
    apt-get update && \
    apt-get install --yes --no-install-recommends ${BUILD_DEPS}

COPY . /src

RUN \
    mkdir /local && \
    cd /tmp && \
    git clone https://github.com/nsone/PcapPlusPlus.git

RUN \
    cd /tmp/PcapPlusPlus && \
    ./configure-linux.sh --install-dir /local && \
    make libs && \
    make install

RUN \
    mkdir /tmp/build && \
    cd /tmp/build && \
    PKG_CONFIG_PATH=/local/lib/pkgconfig cmake -DMMDB_ENABLE=true -DCMAKE_BUILD_TYPE=RelWithDebInfo /src && \
    make all test

RUN \
    cd /tmp/build && \
    go get github.com/pkg/errors && \
    go get github.com/jroimartin/gocui && \
    go get github.com/docopt/docopt-go && \
    go build /src/cmd/pktvisor/pktvisor.go

FROM debian:buster-slim AS runtime

ENV RUNTIME_DEPS "curl libpcap0.8 libmaxminddb0"

RUN \
    apt-get update && \
    apt-get install --yes --no-install-recommends ${RUNTIME_DEPS} && \
    rm -rf /var/lib/apt

COPY --from=build /tmp/build/pktvisord /usr/local/sbin/pktvisord
COPY --from=build /tmp/build/pktvisor /usr/local/bin/pktvisor
COPY entry.sh /usr/local/bin/

ENTRYPOINT [ "entry.sh" ]

