### pktvisor Collection Policies

## Summary

Collection policies direct pktvisor to use Taps (#75) to create an instance of an input stream (possibly with a filter),
and attach handlers to it. Processing takes place, and the data is exposed for sinks to collect. These policies may be
given directly to pktvisor via command line or through the Admin API if available.

Policies require a `kind` to indicate the type of policy being applied.

NOTE: this is not yet a complete, formal specification, and not all of it is implemented. See src/tests/test_policies.cpp for current, tested implementation.

`collection-policy-anycast.yaml`

```yaml
version: "1.0"

visor:
  policies:
    # policy name and description
    anycast_dns:
      kind: collection
      description: "base anycast DNS policy"
      # input stream to create based on the given tap and optional filter config
      input:
        # this must reference a tap name, or application of the policy will fail
        tap: anycast
        # this must match the input_type of the matching tap name, or application of the policy will fail
        input_type: pcap
        filter:
          bpf: "port 53"
      # stream handlers to attach to this input stream
      # these decide exactly which data to summarize and expose for collection
      handlers:
        # default configuration for the stream handlers
        config:
          periods: 5
          max_deep_sample: 50
        modules:
          # the keys at this level are unique identifiers
          default_net:
            type: net
          udp_traffic:
            type: net
            filter:
              protocols: [ udp ]
            metrics:
              enable:
                - top_ips
          default_dns:
            type: dns
            config:
              max_deep_sample: 75
            # time window analyzers
            analyzers:
              modules:
                nx_attack:
                  type: dns_random_label
          special_domain:
            type: dns
            # specify that the stream handler module requires >= specific version to be successfully applied 
            require_version: "1.0"
            filter:
              # must match the available configuration options for this version of this stream handler
              qname_suffix: .mydomain.com
            metrics:
              disable:
                - top_qtypes
                - top_udp_ports
```

## REST API

CRUD on Collection Policies for a running pktvisord instance is possible if the Admin API is active.

`/api/v1/policies`

`/api/v1/policies/:id:`

## Standalone Command Line Example

```shell
$ pktvisord --config taps.yaml --config collection-policy-anycast.yaml
```

They may also be combined into a single YAML file (the schemas will merge) and passed in with one `--config` option.

The REST API (or prometheus output, pktvisor-cli, etc) should then be used to collect the results manually.

