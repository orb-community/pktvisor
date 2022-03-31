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
