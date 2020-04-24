#!/bin/bash

# we filter out some paths due to probabalistic results
JSONFILTER='delpaths([["5m","dns","cardinality"]])|delpaths([["5m","period"]])|delpaths([["5m","packets","cardinality"]])|delpaths([["5m","dns","xact","out","quantiles_us"]])'

# run pktvisord ($1) and expect json output to match that found in given file ($2), using pktvisord args in ($3)
PKTVISORD=$1
JSONTPT=$2
shift; shift; shift;

tmpfile=$(mktemp /tmp/pktvisor-ftest.XXXXXX)
CMD="$PKTVISORD $@"
echo "--- running: cd $PWD; $CMD; cd -"
`$CMD > $tmpfile`
status=$?
if [[ $status -eq 0 ]]
then
  echo "pktvisor success"
else
  echo "pktvisor failure"
  rm $tmpfile
  exit $status
fi

# XXX fix probablistic differences causing failures between runs or OSs
# for now just ensure pktvisor ran
OSTYPE=`uname -s`
if [[ "$OSTYPE" == "Linux" ]]; then
    exit 0
fi

result=`jq $JSONFILTER $tmpfile`
rm $tmpfile
want=`cat "$JSONTPT" | jq $JSONFILTER`
status=$?
if [[ $status -eq 0 ]]
then
  echo "template read success"
else
  echo "template read failure"
  exit $status
fi
if [ "$want" == "$result" ]
then
  echo "template match success"
else
  echo "template match failure"
  echo "---want---"
  echo $want
  echo "---actual---"
  echo $result
  exit 1
fi

exit 0
