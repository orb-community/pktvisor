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

Scenario: create a policy
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy
  Then 2 policies must be running

Scenario: delete all policies
  Given that a pktvisor instance is running on port default with admin permission
  When delete 1 policies
  Then 0 policies must be running

Scenario: delete 1 policy
  Given that a pktvisor instance is running on port default with admin permission
  When create a new policy
    And delete 1 policies
  Then 1 policies must be running