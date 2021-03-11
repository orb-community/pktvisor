![pktvisor](docs/images/pktvisor-header.png)

> This project is in [active development](https://github.com/ns1/community/blob/master/project_status/ACTIVE_DEVELOPMENT.md).

![Build status](https://github.com/ns1/pktvisor/workflows/Build/badge.svg)
[![LGTM alerts](https://img.shields.io/lgtm/alerts/g/ns1/pktvisor.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/ns1/pktvisor/alerts/)
[![Coverity alerts](https://img.shields.io/coverity/scan/22731.svg)](https://scan.coverity.com/projects/ns1-pktvisor)

<p align="left">
  <strong>
    <a href="#what-is-pktvisor">Introduction<a/>&nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="#get-started">Get Started<a/>&nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="#docs">Docs<a/>&nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="#build">Build<a/>&nbsp;&nbsp;&bull;&nbsp;&nbsp;
    <a href="#contribute">Contribute<a/>&nbsp;&nbsp;&bull;&nbsp;&nbsp;    
    <a href="#contact-us">Contact Us<a/>
  </strong>
</p>

## What is pktvisor?

**pktvisor** (pronounced "packet visor") is an **observability tool** for _summarizing_ high volume, information
overloaded data streams directly at the edge. Its goal is to extract the useful signal from the less useful noise; to
separate the needles from the haystacks as close to the source as possible. This results in lightweight, immediately
actionable observability data at a tiny fraction of the raw data size.

It is a resource efficient, side-car style agent built from the ground up to be dynamically controlled in real time via
API. Its output is useful both on-node via command line (for a localized, hyper real-time view) as well as centrally
collected into industry standard observability stacks like Prometheus and Grafana.

The modular input stream system is designed to _tap into_ data streams, and currently focuses
on [packet capture](https://en.wikipedia.org/wiki/Packet_analyzer) but will soon support additional taps such
as [sFlow](https://en.wikipedia.org/wiki/SFlow) / [Netflow](https://en.wikipedia.org/wiki/NetFlow)
, [dnstap](https://dnstap.info/), [envoy taps](https://www.envoyproxy.io/docs/envoy/latest/operations/traffic_tapping),
and [eBPF](https://ebpf.io/).

The modular, real-time stream processor includes full application level analysis, and typically summarizes to one minute
buckets of:

* Counters
* Histograms and Quantiles
* Timers and Rates
* Heavy Hitters/Frequent Items/Top N
* Set Cardinality
* GeoIP

pktvisor has its origins in observability of critical internet infrastructure, including traffic engineering and DDoS
protection.

These screenshots display both the command line and centralized views of
the [Network](https://github.com/ns1/pktvisor/tree/master/src/handlers/net)
and [DNS](https://github.com/ns1/pktvisor/tree/master/src/handlers/dns) stream processors, and the types of summary
information provided:

![Image of CLI UI](docs/images/pktvisor3-cli-ui-screenshot.png)
![Image of Grafana Dash](docs/images/pktvisor3-grafana-screenshot.png)

## Get Started

### Docker

The easiest way to get started with pktvisor is to use
the [public docker image](https://hub.docker.com/r/ns1labs/pktvisor). The image contains the collector
agent (`pktvisord`), the command line UI (`pktvisor-cli`), and the pcap file analyzer (`pktvisor-pcap`). When running
the container, you specify which tool to run.

1. *Pull the container*

```
docker pull ns1labs/pktvisor
``` 

2. *Start the collector agent*

This will start in the background and stay running. Note that the final two arguments select `pktvisord` agent and
the `any` ethernet interface for packet capture. You may substitute `any` for a known interface on your device, such
as `eth0`. _Note that this step requires docker host networking_ to observe traffic outside the container, and that only
Linux supports host networking currently:

```
docker run --rm --net=host -d ns1labs/pktvisor pktvisord any
```

3. *Run the command line UI*

After the agent is running, you can observe results locally with the included command line UI. This command will run the
UI (`pktvisor-cli`) in the foreground, and exit when Ctrl-C is pressed. It connects to the running agent locally using
the built in [REST API](https://app.swaggerhub.com/apis/ns1labs/pktvisor/3.1.0#/).
```
docker run -it --rm --net=host ns1labs/pktvisor pktvisor-cli
```

### Other Installation Methods

There are currently no prebuilt packages besides Docker, _although we are working on additional installation methods_.
If you have a preferred method you would like to see support
for, [please create an issue](https://github.com/ns1/pktvisor/issues/new). Until then, you may build your own
executable, please see the [Build](#build) section below.

## Docs

### Agent Usage

A collector agent should be installed on each node to be monitored.

Current command line options are described with:

```
docker run --rm ns1labs/pktvisor pktvisord --help
```

```

    Usage:
      pktvisord [options] [IFACE]
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes data streams and exposes a REST API control plane for configuration and metrics.

    IFACE, if specified, is either a network interface or an IP address (4 or 6). If this is specified,
    a "pcap" input stream will be automatically created, with "net" and "dns" handler modules attached.
    ** Note that this is deprecated; you should instead use --admin-api and create the pcap input stream via API.

    Base Options:
      -l HOST               Run webserver on the given host or IP [default: localhost]
      -p PORT               Run webserver on the given port [default: 10853]
      --admin-api           Enable admin REST API giving complete control plane functionality [default: false]
                            When not specified, the exposed API is read-only access to summarized metrics.
                            When specified, write access is enabled for all modules.
      -h --help             Show this screen
      -v                    Verbose log output
      --no-track            Don't send lightweight, anonymous usage metrics.
      --version             Show version
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
    Handler Module Defaults:
      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]
    pcap Input Module Options (deprecated, use admin-api instead):
      -b BPF                Filter packets using the given BPF string
      -H HOSTSPEC           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                            from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                            Specifying this for live capture will append to any automatic detection.

```

### Command Line UI Usage

The command line UI (`pktvisor-cli`) connects directly to a pktvisord agent to visualize the real time stream
summarization, which is by default a sliding 5 minute time window. It can also connect to a remote agent.

```
docker run --rm ns1labs/pktvisor pktvisor-cli --help
```

```

Usage:
  pktvisor-cli [-p PORT] [-H HOST]
  pktvisor-cli -h
  pktvisor-cli --version

  -H string
    	Query pktvisord metrics webserver on the given host (default "localhost")
  -h	Show help
  -p int
    	Query pktvisord metrics webserver on the given port (default 10853)
  -version
    	Show client version

```

### pcap File Analysis

`pktvisor-pcap` is a tool that can statically analyze prerecorded packet capture files. It takes many of the same
options, and does all of the same analysis, as the live agent version.

```

docker run --rm ns1labs/pktvisor pktvisor-pcap --help

```

```

    Usage:
      pktvisor-pcap [options] PCAP
      pktvisor-pcap (-h | --help)
      pktvisor-pcap --version

    Summarize a pcap file. The result will be written to stdout in JSON format, while console logs will be printed
    to stderr.

    Options:
      --max-deep-sample N   Never deep sample more than N% of streams (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory. Use 1 to summarize all data. [default: 5]
      -h --help             Show this screen
      --version             Show version
      -v                    Verbose log output
      -b BPF                Filter packets using the given BPF string
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
      -H HOSTSPEC           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                            from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                            Specifying this for live capture will append to any automatic detection.

```

You can use the docker container by passing in a volume referencing the directory containing the pcap file. The standard
output will contain the JSON summarization output, which you can capture or pipe into other tools, for example:
```

$ docker run --rm -v /pktvisor/src/tests/fixtures:/pcaps ns1labs/pktvisor pktvisor-pcap /pcaps/dns_ipv4_udp.pcap | jq .

[2021-03-11 18:45:04.572] [pktvisor] [info] Load input plugin: PcapInputModulePlugin dev.vizer.module.input/1.0
[2021-03-11 18:45:04.573] [pktvisor] [info] Load handler plugin: DnsHandler dev.vizer.module.handler/1.0
[2021-03-11 18:45:04.573] [pktvisor] [info] Load handler plugin: NetHandler dev.vizer.module.handler/1.0
...
processed 140 packets
{
  "5m": {
    "dns": {
      "cardinality": {
        "qname": 70
      },
      "period": {
        "length": 6,
        "start_ts": 1567706414
      },
      "top_nxdomain": [],
      "top_qname2": [
        {
          "estimate": 140,
          "name": ".test.com"
        }
      ],
...     
```

### Metrics Collection

The metrics are available from the agent in JSON format via the [REST API](#rest-api).

For most use cases, you will want to collect the most recent full 1-minute bucket, once per minute:

```
curl localhost:10853/api/v1/metrics/bucket/1
```

This can be done with tools like [telegraf](https://docs.influxdata.com/telegraf/) and
the [standard HTTP plugin](https://github.com/influxdata/telegraf/blob/release-1.17/plugins/inputs/http/README.md).
Example telegraf config snippet:

```

[inputs]
[[inputs.http]]
urls = [ "http://127.0.0.1:10853/api/v1/metrics/bucket/1",]
interval = "60s"
data_format = "json"
json_query = "1m"
json_time_key = "period_start_ts"
json_time_format = "unix"
json_string_fields = [
  "dns_*",
  "packets_*",
]

[inputs.http.tags]
t = "pktvisor"
interval = "60"

```

#### Prometheus

`pktvisord` will have native Prometheus support in version 3.2.0. Until
then, [an adapter is available](https://github.com/ns1/pktvisor/tree/master/reporting/pktvisor_prometheus) in the
repository.

### REST API

REST API documentation, including a description of the metrics that are available, is available
in [OpenAPI Format](https://app.swaggerhub.com/apis/ns1labs/pktvisor/3.1.0#/)

Please note that the administration control plane API is currently undergoing heavy iteration and so is not yet
documented. If you have a use case that requires the administration API, please [contact us](#contact-us) to discuss.

### Advanced Agent Example

Starting the collector agent from Docker with MaxmindDB GeoIP/GeoASN support and using the Host option to identify
ingress and egress traffic:

```
docker run --rm --net=host -d \
    --mount type=bind,source=/opt/geo,target=/geo \
    ns1labs/pktvisor pktvisord \
    --geo-city /geo/GeoIP2-City.mmdb \
    --geo-asn /geo/GeoIP2-ISP.mmdb \
    -H 192.168.0.54/32,127.0.0.1/32 \
    eth0
```

### Further Documentation

We recognize the value of first class documentation, and this section is being expanded.
Please [contact us](#contact-us) if you have any questions on installation, use, or development.

## Contact Us

We are _very_ interested in hearing about your use cases, feature requests, and other feedback!

* [File an issue](https://github.com/ns1/pktvisor/issues/new)
* Use our [public feature board](https://github.com/ns1/pktvisor/projects/1)
* Start a [Discussion](https://github.com/ns1/pktvisor/discussions)
* [Join us on Slack](https://join.slack.com/t/getorb/shared_invite/zt-nn4joou9-71Bp3HkubYf5Adh9c4cDNw)
* Send mail to [info@pktvisor.dev](mailto:info@pktvisor.dev)

## Build

The main code base is written in clean, modern C++. The `pktvisor-cli` command line interface is written in Go. The
build system requires CMake and the [Conan](https://conan.io/) package manager system.

pktvisor adheres to [semantic versioning](https://semver.org/).

#### Dependencies

* Linux or OSX
* [Conan](https://conan.io/) C++ package manager
* CMake >= 3.13 (`cmake`)
* C++ compiler supporting C++17
* MaxMind DB (`libmaxmindb-dev`)
* [PcapPlusPlus](https://github.com/ns1/PcapPlusPlus) (NS1 fork)

In addition, debugging integration tests requires:

* [jq](https://stedolan.github.io/jq/)
* [graphtage](https://github.com/trailofbits/graphtage)

#### Building

The general build steps are:

```
$ git clone https://github.com/ns1/pktvisor.git
$ cd pktvisor
$ mkdir build && cd build
$ conan install ..
$ cmake ..
$ make all test
$ bin/pktvisord --help
```

As development environments can vary widely, please see
the [Dockerfile](https://github.com/ns1/pktvisor/blob/master/docker/Dockerfile)
and [Continuous Integration build file](https://github.com/ns1/pktvisor/blob/master/.github/workflows/cmake.yml) for
reference.

## Contribute

Thanks for considering contributing! We will expand this section with more detailed information to guide you through the
process.

Please open Pull Requests against the `develop` branch. If you are considering a larger
contribution, [please contact us](#contact-us) to discuss your design.

See the [NS1 Contribution Guidelines](https://github.com/ns1/community) for more information.

## License

This code is released under Mozilla Public License 2.0. You can find terms and conditions in the LICENSE file.
