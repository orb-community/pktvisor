from typing import Any
from metrics import from_str, from_none, from_union
from behave import step
from utils import random_string, threading_wait_until, make_get_request, make_delete_request, create_tags_set
import yaml
from yaml.loader import SafeLoader
import requests
from hamcrest import *
from random import sample


@step("a user creates a new {tap_type} tap with {amount_of_tags} tag(s)")
def create_new_tap(context, tap_type, amount_of_tags):
    assert_that(tap_type, any_of(equal_to("pcap"), equal_to("flow"), equal_to("dnstap")), "Unexpected tap type")
    tags_set = create_tags_set(amount_of_tags)
    if context.role == "admin":
        expected_status_code = 200
    else:
        expected_status_code = 404
    context.tap_name = random_string(10)
    if tap_type == "pcap":
        tap_yaml = Taps.generate_pcap_tap(context.tap_name, context.mock_iface_name)
    elif tap_type == "flow":
        tap_yaml = Taps.generate_flow_tap(context.tap_name)
    else:
        tap_yaml = Taps.generate_dnstap_tap(context.tap_name)
    policy_yaml_parsed = yaml.load(tap_yaml, Loader=SafeLoader)
    if "existing_taps" in context:
        context.existing_taps.update({context.tap_name: tags_set})
    else:
        context.existing_taps = {context.tap_name: tags_set}
    if len(tags_set) > 0:
        tags_set = {"tags": tags_set}
        policy_yaml_parsed['visor']['taps'][context.tap_name].update(tags_set)
    yaml_tap_data = yaml.dump(policy_yaml_parsed)
    response = create_tap(yaml_tap_data, context.pkt_port, expected_status_code)
    assert_that(response.status_code, equal_to(expected_status_code),
                f"Taps creation failed with {response.status_code}:{response.text}")
    if len(tags_set) > 0:
        assert_that(len(response.json()[context.tap_name]['tags']), equal_to(int(amount_of_tags)),
                    f"Unexpected amount of tags on tap {context.tap_name}.\n Tap: {response.json()}")


@step("a user makes a GET request on the {tap_endpoint} endpoint")
def get_taps_endpoint(context, tap_endpoint):
    assert_that(tap_endpoint, any_of(equal_to("taps"), equal_to("taps/default")), "Unexpected endpoint for tap")
    context.taps_response_json = make_get_request(tap_endpoint, context.pkt_port, 200).json()


@step("the tap endpoint must be available with the default tap")
def check_default_tap(context):
    assert_that("default" in context.taps_response_json.keys(), is_(True), "Default tap not present on taps endpoint")
    DefaultPcap.check_default_pcap(context.taps_response_json, "default")


@step("the new {tap_type} tap should be accessible and correctly created")
def check_new_tap(context, tap_type):
    assert_that(tap_type, any_of(equal_to("pcap"), equal_to("flow"), equal_to("dnstap")))
    tap_endpoint = f"taps"
    context.taps_response_json = make_get_request(tap_endpoint, context.pkt_port, 200).json()
    if tap_type == "pcap":
        DefaultPcap.check_default_pcap(context.taps_response_json, context.tap_name)
        tap_endpoint = f"taps/{context.tap_name}"
        context.tap_pcap_response_json = make_get_request(tap_endpoint, context.pkt_port, 200).json()
        DefaultPcap.check_default_pcap(context.tap_pcap_response_json, context.tap_name)
    else:  # todo other taps
        raise "Only pcap is supported for now"


@step("a user remove {amount_of_taps} tap(s)")
def remove_tap(context, amount_of_taps):
    taps_endpoint = f"taps"
    if amount_of_taps.isnumeric():
        amount_of_taps = int(amount_of_taps)
        taps_to_be_removed = sample(context.existing_taps.keys(), amount_of_taps)
    else:
        assert_that(amount_of_taps, equal_to("all"), "Unexpected amount of taps. Use an integer or 'all'")
        taps_to_be_removed = list(make_get_request(taps_endpoint, context.pkt_port, 200).json().keys())
    for tap in taps_to_be_removed:
        tap_endpoint = f"taps/{tap}"
        response = make_delete_request(tap_endpoint, context.pkt_port, 200)
        assert_that(response.status_code, equal_to(200), f"Failed to removed tap {tap}")
    response_json = make_get_request(taps_endpoint, context.pkt_port, 200).json()
    if response_json is None:
        remaining_taps = list()
    else:
        remaining_taps = list(response_json.keys())
    any_remaining_tap = any(tap in remaining_taps for tap in taps_to_be_removed)
    assert_that(any_remaining_tap, is_(False), f"Remaining taps contains taps that should be removed. \n"
                                               f"Remaining: {remaining_taps}. \n"
                                               f"Removed: {taps_to_be_removed}.")


@step("{amount_of_taps} tap(s) must exist")
def check_amount_of_taps(context, amount_of_taps):
    amount_of_taps = int(amount_of_taps)
    amount_remaining_taps = check_until_amount_of_taps(amount_of_taps, context.pkt_port)
    assert_that(amount_remaining_taps, equal_to(amount_of_taps), "Unexpected amount of taps existing")


@threading_wait_until
def check_until_amount_of_taps(amount_of_taps, pkt_port, expected_status_code=200, event=None):
    tap_endpoint = f"taps"
    response_json = make_get_request(tap_endpoint, pkt_port, 200).json()
    if response_json is None:
        remaining_taps = list()
    else:
        remaining_taps = list(response_json.keys())
    if len(remaining_taps) == amount_of_taps:
        event.set()
        return len(remaining_taps)
    return len(remaining_taps)


@threading_wait_until
def create_tap(yaml_data, pkt_port=10853, expected_status_code=201, event=None):
    """
    :param yaml_data: tap configurations
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :param event: threading.event
    :return: response
    """
    event.wait(1)
    pkt_api = f"http://localhost:{pkt_port}/api/v1/taps"
    headers_request = {'Content-type': 'application/x-yaml'}
    response = requests.post(pkt_api, data=yaml_data, headers=headers_request)
    if response.status_code == int(expected_status_code):
        event.set()
        return response
    return response


class Pcap:
    config: dict
    input_type: str
    interface: str
    tags: None

    def __init__(self, config: dict, input_type: str, interface: str, tags: None) -> None:
        self.config = config
        self.input_type = input_type
        self.interface = interface
        self.tags = tags

    @staticmethod
    def pcap_config(obj: Any) -> 'dict':
        assert isinstance(obj, dict)
        from_union([from_none, from_str], obj.get("host_spec"))
        from_str(obj.get("iface"))
        return obj

    @staticmethod
    def check_pcap(obj: Any) -> 'Pcap':
        assert isinstance(obj, dict)
        config = Pcap.pcap_config(obj.get("config"))
        input_type = from_str(obj.get("input_type"))
        interface = from_str(obj.get("interface"))
        tags = from_none(obj.get("tags"))
        return Pcap(config, input_type, interface, tags)


class DefaultPcap:
    default: Pcap

    def __init__(self, default: Pcap) -> None:
        self.default = default

    @staticmethod
    def check_default_pcap(obj: Any, tap_name: str) -> 'DefaultPcap':
        assert isinstance(obj, dict)
        default = Pcap.check_pcap(obj.get(tap_name))
        return DefaultPcap(default)


class Taps:
    def __init__(self):
        pass

    @classmethod
    def generate_pcap_tap(cls, name, iface):
        tap_yaml = f"""
            version: "1.0"
        
            visor:
              taps:
               {name}:
                 input_type: pcap
                 config:
                   iface: {iface}
            """
        return tap_yaml

    @classmethod
    def generate_flow_tap(cls, name):
        tap_yaml = f"""
            version: "1.0"
        
            visor:
              taps:
               {name}:
                 input_type: flow
            """
        return tap_yaml

    @classmethod
    def generate_dnstap_tap(cls, name):
        tap_yaml = f"""
            version: "1.0"
        
            visor:
              taps:
               {name}:
                 input_type: dnstap
            """
        return tap_yaml
