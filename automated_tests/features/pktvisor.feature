@AUTORETRY
Feature: pktvisor tests

@smoke
Scenario: pktvisor bootstrap
  When run pktvisor instance on port available with user permission
  Then the pktvisor container status must be running
    And pktvisor API must be enabled
    And 2 policies must be running


@smoke
Scenario: run multiple pktvisors instances using different ports
  When run pktvisor instance on port available with user permission
    And run pktvisor instance on port available with user permission
    And run pktvisor instance on port available with user permission
  Then 3 pktvisor's containers must be running


@smoke
Scenario: run multiple pktvisors instances using the same port
  When run pktvisor instance on port available with user permission
    And run pktvisor instance on port unavailable with user permission
  Then 1 pktvisor's containers must be running
    And 1 pktvisor's containers must be exited


@smoke
Scenario Outline: create a policy with all handlers using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with all handler(s) and tap default
    And run mocked data <file_name> for this network
  Then 4 policies must be running
#1 policy default, 2 policies with resources and 1 policy created
    And metrics must be correctly generated for <traffic_type> traffic
  Examples:
    |file_name| traffic_type |
    | dhcp-flow.pcap | dhcp  |
    | dns_ipv6_udp.pcap| dns |


@smoke
Scenario Outline: create a policy with net handler using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with net handler(s) and tap default
    And run mocked data <file_name> for this network
  Then 4 policies must be running
    And metrics must be correctly generated for <traffic_type> traffic
  Examples:
    |file_name| traffic_type |
    | dhcp-flow.pcap | dhcp  |
    | dns_ipv6_udp.pcap| dns |

@smoke
Scenario Outline: create a policy with dhcp handler using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with dhcp handler(s) and tap default
    And run mocked data <file_name> for this network
  Then 4 policies must be running
    And metrics must be correctly generated for <traffic_type> traffic
  Examples:
    |file_name| traffic_type |
    | dhcp-flow.pcap | dhcp  |
    | dns_ipv6_udp.pcap| dns |


@smoke
Scenario Outline: create a policy with dns handler using admin permission
  Given that a pktvisor instance is running on port <status_port> with <role> permission
  When create a new policy with dns handler(s) and tap default
    And run mocked data <file_name> for this network
  Then 4 policies must be running
    And metrics must be correctly generated for <traffic_type> traffic
  Examples:
    | status_port | role | file_name | traffic_type |
    | available   | admin | dhcp-flow.pcap | dhcp   |
    | available   | admin | dns_ipv6_udp.pcap | dns |
    | available   | admin | dns_ipv6_tcp.pcap | dns |
    | available   | admin | dns_ipv4_udp.pcap | dns |
    | available   | admin | dns_ipv4_tcp.pcap | dns |
    | available   | admin | dns_udp_mixed_rcode.pcap | dns |

@smoke
Scenario: create a policy with pcap stats handler using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with pcap_stats handler(s) and tap default
  Then 4 policies must be running


@smoke
Scenario: delete the default policy using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When delete 1 non-resource policies
  Then 0 policies must be running


@smoke
Scenario: delete all non-resource policies using admin permission
  Given that a pktvisor instance is running on port available with admin permission
    And create a new policy with all handler(s) and tap default
  When delete 2 non-resource policies
  Then 0 policies must be running


@smoke
Scenario: delete 1 non-resource policy using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with all handler(s) and tap default
    And delete 1 non-resource policies
  Then 2 policies must be running


@smoke
Scenario: delete the default-resource policy using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When delete 1 resource policies
  Then 1 policies must be running


@smoke
Scenario: delete all resource policies using admin permission
  Given that a pktvisor instance is running on port available with admin permission
    And create a new policy with all handler(s) and tap default
  When delete 2 resource policies
  Then 2 policies must be running


@smoke
Scenario: delete 1 resource policy using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with all handler(s) and tap default
    And delete 1 resource policies
  Then 3 policies must be running


@smoke
Scenario: create a policy using user permission
  Given that a pktvisor instance is running on port available with user permission
  When try to create a new policy with all handler(s)
  Then status code returned on response must be 404
    And 2 policies must be running


@smoke
Scenario: delete 1 policy using user permission
  Given that a pktvisor instance is running on port available with user permission
  When try to delete a policy
  Then status code returned on response must be 404
    And 2 policies must be running


@smoke
Scenario Outline: pktvisor metrics
  When run pktvisor instance on port <status_port> with <role> permission
    And run mocked data <file_name> for this network
  Then the pktvisor container status must be <pkt_status>
    And pktvisor API must be enabled
    And metrics must be correctly generated for <traffic_type> traffic
  Examples:
    | status_port | role | file_name | pkt_status | traffic_type |
    | available   | user | dhcp-flow.pcap | running    | dhcp   |
    | available   | user | dns_ipv6_udp.pcap | running    | dns |
    | available   | user | dns_ipv6_tcp.pcap | running    | dns |
    | available   | user | dns_ipv4_udp.pcap | running    | dns |
    | available   | user | dns_ipv4_tcp.pcap | running    | dns |
    | available   | user | dns_udp_mixed_rcode.pcap | running    | dns |


@smoke
Scenario Outline: pktvisor bucket metrics dns traffic
  Given that a pktvisor instance is running on port <status_port> with <role> permission
  When run mocked data <file_name> for this network
  Then Metrics must go through the 5 bucket(s) queue correctly
  Examples:
    | status_port | role | file_name |
    | available   | user | dns_ipv6_udp.pcap |


@smoke
Scenario Outline: pktvisor bucket metrics dhcp traffic
  Given that a pktvisor instance is running on port <status_port> with <role> permission
  When run mocked data <file_name> for this network
  Then Metrics must go through the 5 bucket(s) queue correctly
  Examples:
    | status_port | role | file_name |
    | available   | user | dhcp-flow.pcap |


@smoke
Scenario Outline: test taps endpoint
  Given that a pktvisor instance is running on port <status_port> with <role> permission
  When a user makes a GET request on the taps endpoint
  Then the tap endpoint must be available with the default tap
  Examples:
    | status_port | role |
    | available   | user |
    | available   | admin |


@smoke
Scenario Outline: test default tap endpoint
  Given that a pktvisor instance is running on port <status_port> with <role> permission
  When a user makes a GET request on the taps/default endpoint
  Then the tap endpoint must be available with the default tap
  Examples:
    | status_port | role |
    | available   | user |
    | available   | admin |


@smoke
Scenario: create new tap through API
  Given that a pktvisor instance is running on port available with admin permission
  When a user creates a new pcap tap with 0 tag(s)
  Then the new pcap tap should be accessible and correctly created
    And 2 tap(s) must exist
    #default tap + created tap


@smoke
Scenario: remove 1 tap
  Given that a pktvisor instance is running on port available with admin permission
    And a user creates a new pcap tap with 0 tag(s)
  When a user remove 1 tap(s)
  Then 1 tap(s) must exist


@smoke
Scenario: remove all taps
  Given that a pktvisor instance is running on port available with admin permission
    And a user creates a new pcap tap with 0 tag(s)
  When a user remove all tap(s)
  Then 0 tap(s) must exist


@smoke
Scenario: create policy selecting 2 taps (matching any)
  Given that a pktvisor instance is running on port available with admin permission
  When a user creates a new pcap tap with 2 tag(s)
    And a user creates a new pcap tap with 2 tag(s)
    And create a new policy with all handler(s) and 1 new and 3 matching existing tag(s). Tap selector: any
  Then 3 tap(s) must exist
    And policy must have 2 inputs
    And defined handlers must be generated for each input
    And 5 policies must be running
    #default + default resource + created + resource for each tap



@smoke
Scenario: create policy selecting 1 tap (matching all)
  Given that a pktvisor instance is running on port available with admin permission
  When a user creates a new pcap tap with 2 tag(s)
    And a user creates a new pcap tap with 2 tag(s)
    And create a new policy with all handler(s) and 0 new and 1 matching existing tag(s). Tap selector: all
  Then 3 tap(s) must exist
    And policy must have 1 inputs
    And defined handlers must be generated for each input
    And 4 policies must be running


@smoke
Scenario: create policy selecting 0 taps (matching all)
  Given that a pktvisor instance is running on port available with admin permission
  When a user creates a new pcap tap with 2 tag(s)
    And a user creates a new pcap tap with 2 tag(s)
    And try to create a new policy with all handler(s) and 1 new and 3 matching existing tag(s). Tap selector: all
  Then policy creation must fail with status: 422 and message: {"error":"no tap match found for specified 'input.tap_selector' tags"}
    And 3 tap(s) must exist
    And 2 policies must be running
    #default + default resource


@smoke
Scenario: create policy selecting 1 taps (matching any)
  Given that a pktvisor instance is running on port available with admin permission
  When a user creates a new pcap tap with 2 tag(s)
    And a user creates a new pcap tap with 2 tag(s)
    And create a new policy with all handler(s) and 1 new and 1 matching existing tag(s). Tap selector: any
  Then 3 tap(s) must exist
    And policy must have 1 inputs
    And defined handlers must be generated for each input
    And 4 policies must be running
