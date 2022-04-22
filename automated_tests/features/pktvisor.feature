Feature: pktvisor tests

Scenario: pktvisor bootstrap
  When run pktvisor instance on port default with user permission
  Then the pktvisor container status must be running
    And pktvisor API must be enabled
    And 1 policies must be running

Scenario: run multiple pktvisors instances using different ports
  When run pktvisor instance on port default with user permission
    And run pktvisor instance on port 10854 with user permission
    And run pktvisor instance on port 10855 with user permission
  Then all the pktvisor containers must be running
    And 3 pktvisor's containers must be running

Scenario: run multiple pktvisors instances using the same port
  When run pktvisor instance on port default with user permission
    And run pktvisor instance on port default with user permission
  Then 1 pktvisor's containers must be running
    And 1 pktvisor's containers must be exited


Scenario: create a policy with all handlers using admin permission
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy with all handler(s)
  Then 2 policies must be running

Scenario: create a policy with net handler using admin permission
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy with net handler(s)
  Then 2 policies must be running

Scenario: create a policy with dhcp handler using admin permission
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy with dhcp handler(s)
  Then 2 policies must be running

Scenario: create a policy with dns handler using admin permission
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy with dns handler(s)
  Then 2 policies must be running

Scenario: create a policy with pcap stats handler using admin permission
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy with pcap_stats handler(s)
  Then 2 policies must be running

Scenario: delete all policies using admin permission
  Given that a pktvisor instance is running on port default with admin permission
  When delete 1 policies
  Then 0 policies must be running

Scenario: delete 1 policy using admin permission
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy with all handler(s)
    And delete 1 policies
  Then 1 policies must be running

Scenario: create a policy using user permission
  Given that a pktvisor instance is running on port 10854 with user permission
  When try to create a new policy with all handler(s)
  Then status code returned on response must be 404
    And 1 policies must be running


Scenario: delete 1 policy using user permission
  Given that a pktvisor instance is running on port default with user permission
  When try to delete a policy
  Then status code returned on response must be 404
    And 1 policies must be running
