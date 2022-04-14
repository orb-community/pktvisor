FROM debian:bullseye-slim AS cppbuild

ENV BUILD_DEPS "g++ cmake make git pkgconf jq python3-pip python3-setuptools ca-certificates libasan6"

RUN \
    apt-get update && \
    apt-get upgrade --yes --force-yes && \
    apt-get install --yes --force-yes --no-install-recommends ${BUILD_DEPS} && \
    pip3 install conan

RUN ls -lha

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

ENTRYPOINT [ "entrypoint.sh" ]

