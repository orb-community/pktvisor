Feature: pktvisor tests

Scenario: pktvisor bootstrap
  When run pktvisor instance on port default
  Then the pktvisor container status must be running
    And pktvisor API must be enabled

Scenario: run multiple pktvisors instances using different ports
  When run pktvisor instance on port default
    And run pktvisor instance on port 10854
    And run pktvisor instance on port 10855
  Then all the pktvisor containers must be running
    And 3 pktvisor's containers must be running

Scenario: run multiple pktvisors instances using the same port
  When run pktvisor instance on port default
    And run pktvisor instance on port default
  Then 1 pktvisor's containers must be running
    And 1 pktvisor's containers must be exited