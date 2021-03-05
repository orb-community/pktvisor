#!/bin/bash

# we filter out some paths due to probabalistic results
JSONFILTER='delpaths([["5m","dns","cardinality"]])|delpaths([["5m","packets","cardinality"]])|delpaths([["5m","dns","xact","out","quantiles_us"]])'

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
echo "--- running: $CMD | jq -c '$JSONFILTER' ---"
$($CMD | jq -c $JSONFILTER >$tmpfile)
status=$?
if [[ $status -eq 0 ]]; then
  echo "pktvisor success"
else
  echo "pktvisor failure"
  rm $tmpfile
  exit $status
fi

OSTYPE=$(uname -s)
CMD="cmp -s $JSONTPT.${OSTYPE}.json $tmpfile"
echo "--- running: $CMD"
result=$($CMD)
status=$?
if [[ $status -eq 0 ]]; then
  rm $tmpfile
  echo "diff success"
  exit 0
else
  echo "diff failure: $result"
fi

# get a diff on bad result
if [[ ! -z "${CTEST_OUTPUT_ON_FAILURE}" ]]; then
  if command -v graphtage &>/dev/null; then
    MAN_CMD="graphtage --from-json --to-json $JSONTPT.${OSTYPE}.json $tmpfile"
    echo "full diff command: $MAN_CMD"
    result=$(graphtage -j --quiet --from-json --to-json $JSONTPT.${OSTYPE}.json $tmpfile)
    status=$?
  fi
fi

# leave failure output for examination later
echo $result
exit $status
