### pktvisor Probe Policies

## Status

**Experimental**: implemented and available for beta testing but the interface may still change

## Summary

Probe policies direct pktvisor to run active network tests and measure various metrics associated with those tests.
Processing takes place, and the data is exposed for sinks to collect. These policies may be
given directly to pktvisor via command line or through the Admin API if available.

Policies require a `kind` to indicate the type of policy being applied.

NOTE: this is not yet a complete, formal specification, and not all of it is implemented. See
src/tests/test_policies.cpp for current, tested implementation.

`probe-policy.yaml`

```yaml
version: "1.0"

visor:
  policies:
    # policy name and description
    probe_ping:
      kind: probe
      description: "base PING test policy"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: default_probe
        # this must match the input_type of the matching tap name, or application of the policy will fail
        input_type: probe
      # stream handlers to attach to this input stream
      # these decide exactly what probe instance will be used to run the tests
      handlers:
        # default configuration for the stream handlers
        config:
          num_periods: 2 #default is 5
          interval_msec: 10000 #default is 5000
          timeout_msec: 2000 #default is 1000
        modules:
          # the keys at this level are unique identifiers
          default_probe:
            type: ping
            config:
              interval_msec: 2000
              timeout_msec: 1000
              packets_per_test: 10 #default 5
              packets_interval_msec: 10 #default 20
              packet_payload_size: 128 #default 56
              disable_scout_packet: true #default is false
              disable_integrity_check: true #default is false
              targets:
                - 192.168.0.1
                - foo.bar
            metric_groups:
              enable:
                - quantiles
                - dns_resolution
                - jitter
```

## REST API

CRUD on Probe Policies for a running pktvisord instance is possible if the Admin API is active.

`/api/v1/policies`

`/api/v1/policies/:id:`

## Standalone Command Line Example

```shell
$ pktvisord --config taps.yaml --config probe-policy.yaml
```

They may also be combined into a single YAML file (the schemas will merge) and passed in with one `--config` option.

The REST API (or prometheus output, pktvisor-cli, etc) should then be used to collect the results manually.

