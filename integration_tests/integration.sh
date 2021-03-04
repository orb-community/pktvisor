#!/bin/bash

# run pktvisor-pcap ($1) and expect json output to match that found in given file ($2), using pktvisor-pcap args in ($3)
PKTVISORPCAP=$1
JSONTPT=$2
shift
shift
shift

if [ $# -eq 0 ]; then
  echo "integration.sh: pktvisor-pcap (1) and expect json output to match that found in given file (2), using pktvisor-pcap args in (3)"
  exit 1
fi

tmpfile=$(mktemp /tmp/pktvisor-ftest.XXXXXX)
CMD="$PKTVISORPCAP $@"
echo "--- running: cd $PWD; $CMD; cd -"
$($CMD >$tmpfile)
status=$?
if [[ $status -eq 0 ]]; then
  echo "pktvisor success"
else
  echo "pktvisor failure"
  rm $tmpfile
  exit $status
fi

OSTYPE=$(uname -s)
result=$(cmp -s $JSONTPT.${OSTYPE}.json $tmpfile)
status=$?
if [[ $status -eq 0 ]]; then
  rm $tmpfile
  echo "diff success"
  exit 0
fi

# get a diff on bad result
if [[ ! -z "${CTEST_OUTPUT_ON_FAILURE}" ]]; then
  if command -v graphtage &>/dev/null; then
    result=$(graphtage -j --quiet --from-json --to-json $JSONTPT.${OSTYPE}.json $tmpfile)
    status=$?
    rm $tmpfile
  fi
fi

echo "diff failure"
echo $result
exit $status
