from hamcrest import *
import requests
import yaml
from yaml.loader import SafeLoader
import random
from behave import step
from utils import make_get_request, random_string, threading_wait_until, create_tags_set, sample_from_dict
import re
from collections import Counter


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


@step("create a new policy with {handler} handler(s) and tap default")
def create_new_policy_tap_default(context, handler):
    create_new_policy(context, handler)


@step(
    "create a new policy with {handler} handler(s) and {amount_new} new and {amount_match} matching existing tag(s). "
    "Tap selector: {type_selector}")
def create_new_policy(context, handler, **kwargs):
    context.policy_name = random_string(10)
    assert_that(handler, any_of(equal_to("all"), equal_to("net"), equal_to("dhcp"),
                                equal_to("dns"), equal_to("pcap_stats")), "Unexpected handler")
    if handler == "all":
        context.amount_of_handlers = 4
    else:
        context.amount_of_handlers = 1
    policy_yaml = Policies.generate_policy(handler, context.policy_name)
    policy_yaml_parsed = yaml.load(policy_yaml, Loader=SafeLoader)
    if "amount_new" in kwargs and "amount_match" in kwargs:
        amount_new = int(kwargs["amount_new"])
        amount_match = int(kwargs["amount_match"])
        if amount_new > 0 or amount_match > 0:
            tags = dict()
            if amount_new > 0:
                tags.update(create_tags_set(kwargs["amount_new"]))
            if amount_match > 0:
                existing_tags_on_taps = tags_from_taps(context.existing_taps)
                assert_that(len(existing_tags_on_taps), greater_than_or_equal_to(amount_match),
                            "number of tags to match exceeds existing amount")
                tags.update(sample_from_dict(existing_tags_on_taps, amount_match))
            selector_dict = {"tap_selector": {kwargs["type_selector"]: [{k: v} for k, v in tags.items()]}}
            del policy_yaml_parsed['visor']['policies'][context.policy_name]['input']['tap']
            policy_yaml_parsed['visor']['policies'][context.policy_name]['input'].update(selector_dict)
            context.taps_matching = return_matching_taps(context.existing_taps, tags, kwargs["type_selector"])
    yaml_policy_data = yaml.dump(policy_yaml_parsed)
    if "pkt_port" and "expected_status_code" in kwargs:
        context.response = assert_policy_creation(yaml_policy_data, kwargs["pkt_port"], kwargs["expected_status_code"])
    elif "pkt_port" in kwargs:
        context.response = assert_policy_creation(yaml_policy_data, kwargs["pkt_port"])
    elif "expected_status_code" in kwargs:
        context.response = assert_policy_creation(yaml_policy_data, context.pkt_port, kwargs["expected_status_code"])
    else:
        context.response = assert_policy_creation(yaml_policy_data, context.pkt_port)


@step("try to create a new policy with {handler} handler(s) and {amount_new} new and {amount_match} matching existing "
      "tag(s). Tap selector: {type_selector}")
def try_to_create_new_policy_without_taps_matching(context, handler, amount_new, amount_match, type_selector):
    create_new_policy(context, handler, amount_new=amount_new, amount_match=amount_match, type_selector=type_selector,
                      pkt_port=context.pkt_port, expected_status_code=422)


@step("policy creation must fail with status: {status_code} and message: {message_error}")
def check_error_policy_creation(context, status_code, message_error):
    assert_that(context.response.status_code, equal_to(int(status_code)), "Unexpected status code for error in policy "
                                                                          "creation")
    assert_that(context.response.text, equal_to(message_error), "Unexpected message error in policy creation")
    names_of_all_policies = make_get_request('policies', context.pkt_port).json().keys()
    assert_that(context.policy_name, not_(is_in(names_of_all_policies)),
                f"policy {context.policy_name} was created even with error response. All policies: "
                f"{names_of_all_policies}")


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
        matching = re.match(r'^default\-[a-zA-Z0-9]+\-resources$', name)
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


@step("policy must have {amount_of_inputs} inputs")
def check_amount_of_inputs(context, amount_of_inputs):
    policy = make_get_request(f"policies/{context.policy_name}", context.pkt_port)
    assert_that(len(policy.json()[context.policy_name]['input']), equal_to(int(amount_of_inputs)),
                f"Unexpected amount of inputs. \n {policy.json()}")
    input_set = set()
    for input_name in set(policy.json()[context.policy_name]['input'].keys()):
        input_set.add(input_name.split('-')[0])
    assert_that(input_set, equal_to(context.taps_matching), "Inputs present in the policy are not the expected ones")


@step("defined handlers must be generated for each input")
def check_handlers_for_input(context):
    policy = make_get_request(f"policies/{context.policy_name}", context.pkt_port)
    all_taps_in_policy = list()
    all_handlers_in_policy = list()
    for key, value in policy.json()[context.policy_name]['modules'].items():
        all_taps_in_policy.append(key.split('-')[1])
        all_handlers_in_policy.append(key.split('-')[2])
    amount_of_each_taps = Counter(all_taps_in_policy)
    amount_of_each_handler = Counter(all_handlers_in_policy)
    for each_input in set(all_taps_in_policy):
        assert_that(amount_of_each_taps[each_input], equal_to(context.amount_of_handlers),
                    f"Incorrect handlers for {each_input} input. {policy.json()}")
    for each_handler in set(all_handlers_in_policy):
        assert_that(amount_of_each_handler[each_handler],
                    equal_to(context.amount_of_handlers * len(context.taps_matching)),
                    f"Incorrect handlers for {each_handler} handler. {policy.json()}")


def assert_policy_creation(yaml_data, pkt_port=10853, expected_status_code=200):
    """

    :param yaml_data: policy configurations
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :return: response
    """
    response = create_policy(yaml_data, pkt_port, expected_status_code)
    assert_that(response.status_code, equal_to(int(expected_status_code)), f"Post request to create a policy failed "
                                                                           f"with status {response.status_code}:"
                                                                           f"{response.text}")
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
                    modules:
                        default-net:
                          type: net
                        default-dhcp:
                          type: dhcp
                        default-dns:
                          type: dns
                        default-pcap_stats:
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
                    modules:
                      default-net:
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
                    modules:
                        default-dhcp:
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
                    modules:
                        default-dns:
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
                    modules:
                        default-pcap_stats:
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


def tags_from_taps(d):
    """

    :param (dict) d: dict to be scanned
    :return: all sub values
    """
    values = dict()
    for key, value in d.items():
        assert isinstance(value, dict)
        values.update(value)
    return values


def return_matching_taps(existing_taps, policy_tags, selector_type):
    """

    :param (dict) existing_taps: dictionary in which the key is the name of the tap and the values are the associated
    tags
    :param (dict) policy_tags: dictionary with the tags linked to policy
    :param (str) selector_type: any or all

    :return (list): taps_matching_policy
    """

    taps_matching = list()

    if selector_type == "any":
        for item in policy_tags.items():
            for tap, tags in existing_taps.items():
                for tag_items in tags.items():
                    if tag_items == item:
                        taps_matching.append(tap)
    elif selector_type == "all":
        for key, value in existing_taps.items():
            if set(policy_tags).issubset(value):
                taps_matching.append(key)
    else:
        raise "Invalid selector type. Options are 'all' or 'any'."
    return set(taps_matching)  # unique taps
