# pktvisor3

```

    Usage:
      pktvisord [-b BPF] [-p PORT] [-H HOSTSPEC] [--periods P] [--summary] [--geo-city FILE] [--geo-asn FILE]
                [--max-deep-sample N]
                TARGET
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord summarizes your data streams.

    TARGET is either a network interface, an IP address (4 or 6) or a pcap file (ending in .pcap or .cap)

    Options:
      -p PORT               Run metrics webserver on the given localhost port [default: 10853]
      -b BPF                Filter packets using the given BPF string
      --geo-city FILE       GeoLite2 City database to use for IP to Geo mapping (if enabled)
      --geo-asn FILE        GeoLite2 ASN database to use for IP to ASN mapping (if enabled)
      --max-deep-sample N   Never deep sample more than N% of packets (an int between 0 and 100) [default: 100]
      --periods P           Hold this many 60 second time periods of history in memory [default: 5]
      --summary             Instead of a time window with P periods, summarize all packets into one bucket for entire time period.
                            Useful for executive summary of (and applicable only to) a pcap file. [default: false]
      -H HOSTSPEC           Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                            from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                            Specifying this for live capture will append to any automatic detection.
      -h --help             Show this screen
      --version             Show version

```

pktvisor summarizes input data streams, and provides a clean, time-windowed HTTP interface to the results.  


Running the server from Docker:
`docker run --rm --net=host -d --mount type=bind,source=/opt/geo,target=/geo --entrypoint '/usr/local/sbin/pktvisord' ns1/pktvisor:latest --geo-city /geo/GeoIP2-City.mmdb --geo-asn /geo/GeoIP2-ISP.mmdb -H 192.168.0.54/32,127.0.0.1/32 any`

Running the console UI from Docker:
`docker run -it --rm --net=host --entrypoint '/bin/bash' ns1/pktvisor:latest -c "sleep 1;pktvisor"`

