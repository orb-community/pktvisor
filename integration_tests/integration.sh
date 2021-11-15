#!/bin/bash

# run pktvisor-pcap ($1) and ensure it completes successfully. output is not checked (see unit tests instead)
PKTVISORPCAP=$1
shift
shift

if [ $# -eq 0 ]; then
  echo "integration.sh: run pktvisor-pcap binary in (1) using pktvisor-pcap args in (2)"
  exit 1
fi

tmpfile=$(mktemp /tmp/pktvisor-ftest.XXXXXX)
CMD="$PKTVISORPCAP $@"
echo "--- running: $CMD ---"
status=$?
if [[ $status -eq 0 ]]; then
  echo "pktvisor-pcap success"
else
  echo "pktvisor-pcap failure"
  rm $tmpfile
  exit $status
fi
