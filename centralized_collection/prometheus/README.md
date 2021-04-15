# Centralized Prometheus Collection

This directory contains resources for building a docker container that it includes pktvisord and
the [Grafana Agent](https://github.com/grafana/agent) for collecting and sending metrics to Prometheus through
[remote write](https://prometheus.io/docs/operating/integrations/#remote-endpoints-and-storage), including cloud
providers.

There is a sample [Grafana dashboard](grafana-dashboard-prometheus.json), which you can also find online in
the [Grafana community dashboards](https://grafana.com/grafana/dashboards/14221) with ID 14221.

Example:

```shell
$ docker pull ns1labs/pktvisor-prom-write
$ docker run -d --mount type=bind,source=/usr/local/geo,target=/geo --net=host --env PKTVISORD_ARGS="--prom-instance <INSTANCE>
--geo-city /geo/GeoIP2-City.mmdb --geo-asn /geo/GeoIP2-ISP.mmdb <INTERFACE>" --env
REMOTE_URL="https://<REMOTEHOST>/api/prom/push" --env USERNAME="<USERNAME>" --env PASSWORD="<PASSWORD>"
ns1labs/pktvisor-prom-write
```

There are a few pieces of information you need to substitute above:

* `<INSTANCE>`: The prometheus "instance" label for all metrics, e.g. "myhost"
* `<INTERFACE>`: The ethernet interface to capture on, e.g. "eth0"
* `<REMOTEHOST>`: The remote host to remote_write the prometheus metric to
* `<USERNAME>`: If required by your prometheus setup, the user name to connect. If not required, leave off this
  environment variable.
* `<PASSWORD>`: If required by your prometheus setup, the password to connect. If not required, leave off this
  environment variable.

Other pktvisor arguments may be passed in the PKTVISORD_ARGS environment variable.
