# Centralized Prometheus Collection

This directory contains resources for building a docker container aiding centralized prometheus collection. It is
published to Docker hub at https://hub.docker.com/r/ns1labs/pktvisor-prom-write

It combines pktvisord with the [Grafana Agent](https://github.com/grafana/agent) for collecting and sending metrics to
Prometheus through
[remote write](https://prometheus.io/docs/operating/integrations/#remote-endpoints-and-storage), including to cloud
providers like [Grafana Cloud](https://grafana.com/products/cloud/).

There is a sample [Grafana dashboard](grafana-dashboard-prometheus.json) which provides a good starting point for
visualizing pktvisor metrics. You can also find it online via
the [Grafana community dashboards](https://grafana.com/grafana/dashboards/14221), allowing you to import easily into any
Grafana installation (ID 14221).

Example:

**PKTVISORD_ARGS requires a semicolon delimited list of arguments*
```shell
docker pull ns1labs/pktvisor-prom-write
docker run -d --net=host --env PKTVISORD_ARGS="--prom-instance <INSTANCE> <INTERFACE>" \
--env REMOTE_URL="https://<REMOTEHOST>/api/prom/push" --env USERNAME="<USERNAME>" \
--env PASSWORD="<PASSWORD>" ns1labs/pktvisor-prom-write
```

Example with Geo enabled (assuming files are located in `/usr/local/geo`):

```shell
docker pull ns1labs/pktvisor-prom-write
docker run -d --mount type=bind,source=/usr/local/geo,target=/geo --net=host --env \
PKTVISORD_ARGS="--prom-instance <INSTANCE> --geo-city /geo/GeoIP2-City.mmdb --geo-asn /geo/GeoIP2-ISP.mmdb <INTERFACE>" \
--env REMOTE_URL="https://<REMOTEHOST>/api/prom/push" --env USERNAME="<USERNAME>" --env PASSWORD="<PASSWORD>" ns1labs/pktvisor-prom-write
```

There are a several pieces of information you need to substitute above:

* `<INSTANCE>`: The prometheus "instance" label for all metrics, e.g. "myhost"
* `<INTERFACE>`: The ethernet interface to capture on, e.g. "eth0"
* `<REMOTEHOST>`: The remote host to remote_write the prometheus metric to
* `<USERNAME>`: If required by your prometheus setup, the user name to connect. If not required, leave off this
  environment variable.
* `<PASSWORD>`: If required by your prometheus setup, the password to connect. If not required, leave off this
  environment variable.

Other pktvisor arguments may be passed in the PKTVISORD_ARGS environment variable.
