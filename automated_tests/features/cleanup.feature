Feature: cleanup env

  @cleanup
  Scenario: remove dummy iface
    Then Remove dummy interface

  @cleanup
  Scenario: remove pktvisor containers
    Then remove pktvisor containers
