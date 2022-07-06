from hamcrest import *
import requests
import yaml
from yaml.loader import SafeLoader
import random
from behave import step
from utils import make_get_request, random_string, threading_wait_until
import re


@step("{amount_of_policies} policies {status_condition} be running")
def assert_amount_of_policies_per_status(context, amount_of_policies, status_condition):
    assert_that(status_condition, any_of(equal_to("must"), equal_to("must not")),
                'Unexpect condition for policy status')
    status_condition_dict = {"must": True, "must not": False}
    all_policies = make_get_request('policies', context.pkt_port).json()
    amount_of_policies_per_status = list()
    for key, value in all_policies.items():
        if value['input'][list(value['input'].keys())[0]]['input']['running'] is status_condition_dict[status_condition]:
            amount_of_policies_per_status.append(key)
    assert_that(len(amount_of_policies_per_status), equal_to(int(amount_of_policies)),
                f"Unexpect amount of policies that {status_condition} be running")


@step("create a new policy with {handler} handler(s)")
def create_new_policy(context, handler, **kwargs):
    policy_yaml = Policies.generate_policy(handler, random_string(10))
    policy_yaml_parsed = yaml.load(policy_yaml, Loader=SafeLoader)
    yaml_policy_data = yaml.dump(policy_yaml_parsed)
    if "pkt_port" and "expected_status_code" in kwargs:
        context.response = assert_policy_creation(yaml_policy_data, kwargs["pkt_port"], kwargs["expected_status_code"])
    elif "pkt_port" in kwargs:
        context.response = assert_policy_creation(yaml_policy_data, kwargs["pkt_port"])
    elif "expected_status_code" in kwargs:
        context.response = assert_policy_creation(yaml_policy_data, context.pkt_port, kwargs["expected_status_code"])
    else:
        context.response = assert_policy_creation(yaml_policy_data, context.pkt_port)


@step("try to create a new policy with {handler} handler(s)")
def try_to_create_new_policy(context, handler):
    create_new_policy(context, handler, pkt_port=context.pkt_port, expected_status_code=404)


@step("delete {amount_of_policies} {policy_type} policies")
def remove_policies(context, amount_of_policies, policy_type):
    resources = list()
    non_resources = list()
    assert_that(policy_type, any_of(equal_to("resource"), equal_to("non-resource")), "Unexpected type of policy")
    names_of_all_policies = make_get_request('policies', context.pkt_port).json().keys()
    for name in names_of_all_policies:
        matching = re.match(r'^.+\-[a-zA-Z0-9]{16}\-resources$', name)
        if matching:
            resources.append(matching.group())
        else:
            assert_that(matching, equal_to(None))
            non_resources.append(name)
    policies_by_type = {"resource": resources, "non-resource": non_resources}
    policies_to_remove = random.sample(policies_by_type[policy_type], int(amount_of_policies))
    for policy in policies_to_remove:
        remove_policy(policy, context.pkt_port)
        response = get_policy(policy, context.pkt_port, 404)
        assert_that(response.json(), has_key('error'), "Unexpected message for non existing policy")
        assert_that(response.json(), has_value('policy does not exists'), "Unexpected message for non existing policy")


@step("try to delete a policy")
def try_to_delete_policies(context):
    names_of_all_policies = make_get_request('policies', context.pkt_port).json().keys()
    sample_policy = random.sample(names_of_all_policies, 1)[0]
    context.response = remove_policy(sample_policy, context.pkt_port, 404)


def assert_policy_creation(yaml_data, pkt_port=10853, expected_status_code=200):
    """

    :param yaml_data: policy configurations
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :return: response
    """
    response = create_policy(yaml_data, pkt_port, expected_status_code)
    assert_that(response.status_code, equal_to(int(expected_status_code)), f"Post request to create a policy failed "
                                                                           f"with status {response.status_code}")
    return response


def get_policy(policy_name, pkt_port=10853, expected_status_code=200):
    """

    :param (str) policy_name: name of the policy to be fetched
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :return: (dict) referred policy data
    """
    endpoint = f"policies/{policy_name}"
    return make_get_request(endpoint, pkt_port, expected_status_code)


def remove_policy(policy_name, pkt_port=10853, expected_status_code=200):

    """
    :param (str) policy_name: name of the policy to be fetched
    :param pkt_port: port on which pktvisor is . Default: 10853
    :param expected_status_code: expected status from response. Default: 204
    :return: response
    """
    pkt_base_api = 'http://localhost:' + str(pkt_port) + '/api/v1/policies/'
    path = pkt_base_api + policy_name
    response = requests.delete(path)
    assert_that(response.status_code, equal_to(int(expected_status_code)),
                f"Delete request of policy {policy_name} failed with status {response.status_code}")
    return response


@threading_wait_until
def create_policy(yaml_data, pkt_port=10853, expected_status_code=201, event=None):
    """

    :param yaml_data: policy configurations
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :param event: threading.event
    :return: response
    """
    event.wait(1)
    pkt_api = f"http://localhost:{pkt_port}/api/v1/policies"
    headers_request = {'Content-type': 'application/x-yaml'}
    response = requests.post(pkt_api, data=yaml_data, headers=headers_request)
    if response.status_code == int(expected_status_code):
        event.set()
        return response
    return response


class Policies:
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
            return Policies.generate_pcap_policy_with_all_handlers(name)
        elif handler == "net":
            return Policies.generate_pcap_policy_with_only_net_handler(name)
        elif handler == "dhcp":
            return Policies.generate_pcap_policy_with_only_dhcp_handler(name)
        elif handler == "dns":
            return Policies.generate_pcap_policy_with_only_dns_handler(name)
        else:
            return Policies.generate_pcap_policy_with_only_pcap_stats_handler(name)
