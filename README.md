# pktvisor3

```

    Usage:
      pktvisord [-b BPF] [-p PORT] [-H HOSTSPEC] [--periods P] TARGET
      pktvisord (-h | --help)
      pktvisord --version

    pktvisord will summarize your packet streams.

    TARGET is either a network interface, an IP address (4 or 6) or a pcap file (ending in .pcap or .cap)

    Options:
      -p PORT          Run metrics webserver on the given port [default: 10853]
      -b BPF           Filter using the given BPF string (live of pcapng only, not pcap)
      --periods P      Hold this many 60 second time periods of history in memory [default: 5]
      -H HOSTSPEC      Specify subnets (comma separated) to consider HOST, in CIDR form. In live capture this /may/ be detected automatically
                       from capture device but /must/ be specified for pcaps. Example: "10.0.1.0/24,10.0.2.1/32,2001:db8::/64"
                       Specifying this for live capture will override any automatic detection.
      -h --help        Show this screen
      --version        Show version

```

Running the server:

`docker run --rm --net=host -d nsone/pktvisor3:latest pktvisord -b 'port 53' enp3s0`

Running the console UI:

`docker -D run --rm --net=host -ti nsone/pktvisor3:latest pktvisor`

