# Packet Capture Stream Input

This directory contains the main packet capture stream input tap.

It uses libpcap or AF_PACKET (Linux) to tap into ethernet interfaces and expose the following events:

* Packet
* UDP Packet
* TCP connection start
* TCP message ready
* TCP connection end

It supports tcpdump compatible bpf filter strings to limit events.

libpcap library has a limitation that traffic may be captured only once per interface per process. AF_PACKET does not
have this limitation.