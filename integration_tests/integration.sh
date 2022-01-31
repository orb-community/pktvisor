#!/bin/bash

# run pktvisor-reader ($1) and ensure it completes successfully. output is not checked (see unit tests instead)
PKTVISORREADER=$1
shift
shift

if [ $# -eq 0 ]; then
  echo "integration.sh: run pktvisor-reader binary in (1) using pktvisor-reader args in (2)"
  exit 1
fi

tmpfile=$(mktemp /tmp/pktvisor-ftest.XXXXXX)
CMD="$PKTVISORREADER $@"
echo "--- running: $CMD ---"
status=$?
if [[ $status -eq 0 ]]; then
  echo "pktvisor-reader success"
else
  echo "pktvisor-reader failure"
  rm $tmpfile
  exit $status
fi
