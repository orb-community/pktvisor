# pktvisor3

```

    Usage:
      pktvisord [-b BPF] [-p PORT] [-H HOSTSPEC] [--periods P] [--summary] [--geo-city FILE] [--geo-asn FILE] TARGET
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord will summarize your packet streams.

    TARGET is either a network interface, an IP address (4 or 6) or a pcap file (ending in .pcap or .cap)

    Options:
      -p PORT          Run metrics webserver on the given localhost port [default: 10853]
      -b BPF           Filter packets using the given BPF string
      --geo-city FILE  GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE   GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
      --periods P      Hold this many 60 second time periods of history in memory [default: 5]
      --summary        Instead of a time window with P periods, summarize all packets into one bucket for entire time period.
                       Useful for executive summary of (and applicable only to) a pcap file. [default: false]
      -H HOSTSPEC      Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                       from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                       Specifying this for live capture will append to any automatic detection.
      -h --help        Show this screen
      --version        Show version

```

Running the server:

`docker run --rm --net=host -d nsone/pktvisor3:latest pktvisord -b 'port 53' enp3s0`

Running the console UI:

`docker -D run --rm --net=host -ti nsone/pktvisor3:latest pktvisor`

