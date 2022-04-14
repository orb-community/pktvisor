FROM debian:bullseye-slim AS cppbuild

ENV BUILD_DEPS "g++ cmake make git pkgconf jq python3-pip python3-setuptools ca-certificates libasan6"

RUN \
    apt-get update && \
    apt-get upgrade --yes --force-yes && \
    apt-get install --yes --force-yes --no-install-recommends ${BUILD_DEPS} && \
    pip3 install conan

RUN ls -lha /home/runner/work/

ENTRYPOINT [ "entrypoint.sh" ]

