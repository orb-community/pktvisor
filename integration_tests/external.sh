#!/bin/bash -x

# if a file called external/run.sh exists, run it.
FILE=external/run.sh
if [[ -f "$FILE" ]]; then
  exec $FILE $1
  exit $?
fi

exit 0
