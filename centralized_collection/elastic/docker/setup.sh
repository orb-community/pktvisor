#!/usr/bin/env bash

export ENDPOINT=${GRAFANA_API:-localhost:3000}

echo "creating data source"
curl -Ss -X POST -H "Content-type: application/json" http://admin:admin@$ENDPOINT/api/datasources --data @./datasource.json

echo
echo "creating dashboard"

TMPFILE=$(mktemp)
trap "rm -rf $TMPFILE" EXIT 
echo "{}" | jq --argfile rawexport ../grafana-dashboard.json '.dashboard += $rawexport | .dashboard.id = null' > $TMPFILE

curl -Ss -X POST -H "Content-type: application/json" http://admin:admin@$ENDPOINT/api/dashboards/db --data @$TMPFILE
