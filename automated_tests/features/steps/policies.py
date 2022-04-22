from hamcrest import *

class policies:
    def __init__(self):
        pass

    @classmethod
    def generate_pcap_policy_with_all_handlers(cls, name):
        policy_yaml = f"""
            version: "1.0"
        
            visor:
              policies:
               {name}:
                 kind: collection
                 input:
                   tap: default
                   input_type: pcap
                 handlers:
                    window_config:
                      num_periods: 5
                      deep_sample_rate: 100
                    modules:
                        net:
                          type: net
                        dhcp:
                          type: dhcp
                        dns:
                          type: dns
                        pcap_stats:
                          type: pcap
            """
        return policy_yaml

    @classmethod
    def generate_pcap_policy_with_only_net_handler(cls, name):
        policy_yaml = f"""
            version: "1.0"
        
            visor:
              policies:
               {name}:
                 kind: collection
                 input:
                   tap: default
                   input_type: pcap
                 handlers:
                    window_config:
                      num_periods: 5
                      deep_sample_rate: 100
                    modules:
                        net:
                          type: net
            """
        return policy_yaml

    @classmethod
    def generate_pcap_policy_with_only_dhcp_handler(cls, name):
        policy_yaml = f"""
            version: "1.0"
        
            visor:
              policies:
               {name}:
                 kind: collection
                 input:
                   tap: default
                   input_type: pcap
                 handlers:
                    window_config:
                      num_periods: 5
                      deep_sample_rate: 100
                    modules:
                        dhcp:
                          type: dhcp
            """
        return policy_yaml
    
    @classmethod
    def generate_pcap_policy_with_only_dns_handler(cls, name):
        policy_yaml = f"""
            version: "1.0"
        
            visor:
              policies:
               {name}:
                 kind: collection
                 input:
                   tap: default
                   input_type: pcap
                 handlers:
                    window_config:
                      num_periods: 5
                      deep_sample_rate: 100
                    modules:
                        dns:
                          type: dns
            """
        return policy_yaml
    
    @classmethod
    def generate_pcap_policy_with_only_pcap_stats_handler(cls, name):
        policy_yaml = f"""
            version: "1.0"
        
            visor:
              policies:
               {name}:
                 kind: collection
                 input:
                   tap: default
                   input_type: pcap
                 handlers:
                    window_config:
                      num_periods: 5
                      deep_sample_rate: 100
                    modules:
                        pcap_stats:
                          type: pcap
            """
        return policy_yaml

    @classmethod
    def generate_policy(cls, handler, name):
        assert_that(handler, any_of(equal_to("all"), equal_to("net"), equal_to("dhcp"),
                                    equal_to("dns"), equal_to("pcap_stats")), "Unexpected handler")
        if handler == "all":
            return policies.generate_pcap_policy_with_all_handlers(name)
        elif handler == "net":
            return policies.generate_pcap_policy_with_only_net_handler(name)
        elif handler == "dhcp":
            return policies.generate_pcap_policy_with_only_dhcp_handler(name)
        elif handler == "dns":
            return policies.generate_pcap_policy_with_only_dns_handler(name)
        else:
            return policies.generate_pcap_policy_with_only_pcap_stats_handler(name)
