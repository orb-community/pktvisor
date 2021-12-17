[![Build Status](https://travis-ci.org/farsightsec/fstrm.png?branch=master)](https://travis-ci.org/farsightsec/fstrm) [![Coverage Status](https://coveralls.io/repos/farsightsec/fstrm/badge.png?branch=master)](https://coveralls.io/r/farsightsec/fstrm?branch=master)

## Overview

This is `fstrm`, a C implementation of the Frame Streams data transport protocol.

Frame Streams is a light weight, binary clean protocol that allows for the transport of arbitrarily encoded data payload sequences with minimal framing overhead -- just four bytes per data frame. Frame Streams does not specify an encoding format for data frames and can be used with any data serialization format that produces byte sequences, such as [Protocol Buffers], [XML], [JSON], [MessagePack], [YAML], etc. Frame Streams can be used as both a streaming transport over a reliable byte stream socket (TCP sockets, TLS connections, `AF_UNIX` sockets, etc.) for data in motion as well as a file format for data at rest. A "Content Type" header identifies the type of payload being carried over an individual Frame Stream and allows cooperating programs to determine how to interpret a given sequence of data payloads.

`fstrm` is an optimized C implementation of Frame Streams that includes a fast, lockless circular queue implementation and exposes library interfaces for setting up a dedicated Frame Streams I/O thread and asynchronously submitting data frames for transport from worker threads. It was originally written to facilitate the addition of high speed binary logging to DNS servers written in C using the [dnstap] log format.

[Protocol Buffers]: https://developers.google.com/protocol-buffers/
[XML]:              http://www.w3.org/TR/xml11/
[JSON]:             http://www.json.org/
[MessagePack]:      http://msgpack.org/
[YAML]:             http://www.yaml.org/
[dnstap]:           http://dnstap.info/


## Building

`fstrm` requires a C99 compiler and the `pkg-config` utility to be installed. If building from a distribution tarball, the following command should build, test, and install `fstrm`:

    ./configure && make && make check && make install

On platforms where the `pkg-config` utility is unavailable, .pc file installation can be disabled by passing `--without-pkgconfigdir` to `configure`.

If building from a git checkout, the `autotools` (`autoconf`, `automake`, `libtool`) must also be installed, and the build system must be bootstrapped by running the `autogen.sh` script:

    ./autogen.sh && ./configure && make && make check && make install

Reference programs `fstrm_capture`, `fstrm_dump`, and `fstrm_replay` are provided. In order to build `fstrm_capture`, the [libevent](http://libevent.org/) library must be installed. The option `--disable-programs` can be passed to `configure` to disable building these programs.

## Synopsis

Include the `fstrm` header file from your C source code:

    #include <fstrm.h>

Compile your C source code. Add the output of the following command to your compile flags:

    pkg-config --cflags libfstrm

Link your C project against the `libfstrm` library. Add the output of the following command to your link flags:

    pkg-config --libs libfstrm

If using autotools to build your C project, the `PKG_CHECK_MODULES` macro can be used to detect the presence of `libfstrm` by adding the following line to your `configure.ac` file:

    PKG_CHECK_MODULES([libfstrm], [libfstrm])

This will place compiler flags in the `libfstrm_CFLAGS` variable and linker flags in the `libfstrm_LIBS` variable. Read [more information here](https://www.flameeyes.eu/autotools-mythbuster/pkgconfig/pkg_check_modules.html) about the `PKG_CHECK_MODULES` macro.

## Documentation

See the [online Doxygen documentation here](http://farsightsec.github.io/fstrm/) for a detailed reference. This documentation can be built from the source tree by running:

    make html

## Versioning

`fstrm` follows the [Semantic Versioning Specification](http://semver.org/).
