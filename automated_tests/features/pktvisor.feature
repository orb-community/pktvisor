Feature: pktvisor tests

Scenario: pktvisor bootstrap
  When run pktvisor instance on port available with user permission
  Then the pktvisor container status must be running
    And pktvisor API must be enabled
    And 2 policies must be running

Scenario: run multiple pktvisors instances using different ports
  When run pktvisor instance on port available with user permission
    And run pktvisor instance on port available with user permission
    And run pktvisor instance on port available with user permission
  Then all the pktvisor containers must be running
    And 3 pktvisor's containers must be running

Scenario: run multiple pktvisors instances using the same port
  When run pktvisor instance on port available with user permission
    And run pktvisor instance on port unavailable with user permission
  Then 1 pktvisor's containers must be running
    And 1 pktvisor's containers must be exited


Scenario: create a policy with all handlers using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with all handler(s)
  Then 4 policies must be running
#1 policy default, 2 policies with resources and 1 policy created

Scenario: create a policy with net handler using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with net handler(s)
  Then 4 policies must be running

Scenario: create a policy with dhcp handler using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with dhcp handler(s)
  Then 4 policies must be running

Scenario: create a policy with dns handler using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with dns handler(s)
  Then 4 policies must be running

Scenario: create a policy with pcap stats handler using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with pcap_stats handler(s)
  Then 4 policies must be running

Scenario: delete all policies using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When delete 2 policies
  Then 2 policies must be running

Scenario: delete 1 policy using admin permission
  Given that a pktvisor instance is running on port available with admin permission
  When create a new policy with all handler(s)
    And delete 1 policies
  Then 2 policies must be running

Scenario: create a policy using user permission
  Given that a pktvisor instance is running on port available with user permission
  When try to create a new policy with all handler(s)
  Then status code returned on response must be 404
    And 2 policies must be running


Scenario: delete 1 policy using user permission
  Given that a pktvisor instance is running on port available with user permission
  When try to delete a policy
  Then status code returned on response must be 404
    And 2 policies must be running


Scenario Outline: pktvisor metrics
  When run pktvisor instance on port <status_port> with <role> permission
    And run mocked data <file_name> for this network
  Then the pktvisor container status must be <pkt_status>
    And metrics must be correctly generated
  Examples:
    | status_port | role | file_name | pkt_status |
    | available   | user | dns_ipv6_udp.pcap | running    |
    | available   | user | dns_ipv6_tcp.pcap | running    |
    | available   | user | dns_ipv4_udp.pcap | running    |
    | available   | user | dns_ipv4_tcp.pcap | running    |
    | available   | user | dhcp-flow.pcap | running    |
    | available   | user | dns_udp_mixed_rcode.pcap | running    |