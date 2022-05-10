from utils import random_string, threading_wait_until
import docker
from behave import step
from test_config import TestConfig, send_terminal_commands
from utils import check_port_is_available, make_get_request
import threading
from hamcrest import *
import os
import json
from deepdiff import DeepDiff

configs = TestConfig.configs()

PKTVISOR_CONTAINER_NAME = "pktvisor-test"


@step("run pktvisor instance on port {status_port} with {role} permission")
def run_pktvisor(context, status_port, role):
    availability = {"available": True, "unavailable": False}

    context.pkt_port = check_port_is_available(availability[status_port])
    context.container_id = run_pktvisor_container("ns1labs/pktvisor", context.pkt_port, role)
    assert_that(context.container_id, not_(equal_to(None)), "Failed to provision pktvisor container")
    event = threading.Event()
    event.wait(1)


@step("that a pktvisor instance is running on port {status_port} with {role} permission")
def pkt_running(context, status_port, role):
    run_pktvisor(context, status_port, role)


@step("status code returned on response must be {status_code}")
def check_response_status_code(context, status_code):
    assert_that(context.response.status_code, equal_to(int(status_code)), "Wrong status code on response")


@step("the pktvisor container status must be {pkt_status}")
def check_pkt_status(context, pkt_status):
    docker_client = docker.from_env()
    container = docker_client.containers.get(context.container_id)
    status = container.status
    assert_that(status, equal_to(pkt_status), f"pktvisor container {context.container_id} failed with status:{status}")


@step("all the pktvisor containers must be {pkt_status}")
def check_pktvisors_status(context, pkt_status):
    docker_client = docker.from_env()

    containers = docker_client.containers.list(all=True)
    for container in containers:
        is_test_container = container.name.startswith(PKTVISOR_CONTAINER_NAME)
        if is_test_container is True:
            status = container.status
            assert_that(status, equal_to(pkt_status), f"pktvisor container {container.id} failed with status:{status}")


@step("{amount_of_pktvisor} pktvisor's containers must be {pkt_status}")
def assert_amount_of_pkt_with_status(context, amount_of_pktvisor, pkt_status):
    containers_with_expected_status = check_amount_of_pkt_with_status(amount_of_pktvisor, pkt_status)
    assert_that(len(set(containers_with_expected_status)), equal_to(int(amount_of_pktvisor)),
                f"Amount of pktvisor container with referred status failed")


@step("pktvisor API must be enabled")
def check_pkt_base_API(context):
    pkt_api_get_endpoints = ['policies',
                             'policies/__all/metrics/bucket/0',
                             'policies/__all/metrics/window/2',
                             'policies/__all/metrics/window/3',
                             'policies/__all/metrics/window/4',
                             'policies/__all/metrics/window/5',
                             'policies/__all/metrics/prometheus']
    event = threading.Event()
    event.wait(0.5)
    for endpoint in pkt_api_get_endpoints:
        make_get_request(endpoint, context.pkt_port)


@step("run mocked data {file_name} for this network")
def run_mocked_data(context, file_name):
    iface = configs.get('iface', 'dummy0')
    cwd = os.getcwd()
    dir_path = os.path.dirname(cwd)
    context.directory_of_network_data_files = f"{dir_path}/automated_tests/features/steps/pcap_files/"
    network_data_files = file_name
    # network_data_files = configs.get("network_data_files") #todo improve logic for multiple files
    assert_that(network_data_files, is_not(None), "Missing values for network_data_files."
                                                  "Please check your test_config.ini file.")
    context.network_data_files = network_data_files.split(", ")

    for network_file in context.network_data_files:
        path_to_file = f"{context.directory_of_network_data_files}{network_file}"
        assert_that(os.path.exists(path_to_file), equal_to(True), f"Nonexistent file {path_to_file}.")
        run_mocked_data_command = f"tcpreplay -i {iface} -tK {context.directory_of_network_data_files}{network_file}"
        tcpreplay_return = send_terminal_commands(run_mocked_data_command, sudo=True)
        assert_that(tcpreplay_return[1], not_(contains_string("command not found")), f"{tcpreplay_return[1]}."
                                                                                     f"Please, install tcpreplay.")


@step("metrics must be correctly generated")
def check_metrics(context):
    pkt_api_get_endpoints = ['policies/default/metrics/window/2',
                             'policies/default/metrics/window/3',
                             'policies/default/metrics/window/4',
                             'policies/default/metrics/window/5'] #todo insert bucket 0
    event = threading.Event()
    event.wait(0.5)
    for network_file in context.network_data_files:
        for endpoint in pkt_api_get_endpoints:

            response_json, json_of_network_data, diff = check_metrics_per_endpoint(endpoint, context.pkt_port,
                                                                             context.directory_of_network_data_files,
                                                                             network_file, timeout=10)
            assert_that(diff, equal_to({}), f"Wrog data generated for {network_file}_{endpoint.replace('/','_')}")


@threading_wait_until
def check_metrics_per_endpoint(endpoint, pkt_port, path_to_file, file_name, event=None):
    endpoint_replaced = endpoint.replace("/", "_")
    response = make_get_request(endpoint, pkt_port)
    # with open(f"/home/arodrigues/Documents/pktvisor/automated_tests/features/steps/pcap_files/{file_name[:-5]}_{endpoint_replaced}.json", "w") as f:
    #     json.dump(response.json(), f, indent=4, sort_keys=True)
    #     f.close()
    file = open(f"{path_to_file}{file_name[:-5]}_{endpoint_replaced}.json", "r")
    json_of_network_data = json.load(file)
    response_json = json.loads(json.dumps(response.json(), sort_keys=True))
    response_json = remove_period_from_json(response_json)
    json_of_network_data = json.loads(json.dumps(json_of_network_data, sort_keys=True))
    json_of_network_data = remove_period_from_json(json_of_network_data)
    diff = DeepDiff(response_json, json_of_network_data)
    if diff == {}:
        event.set()
        return response_json, json_of_network_data, diff
    return response_json, json_of_network_data, diff


def remove_period_from_json(json_file):
    """
    Delete keys with the value "None" in a dictionary, recursively.

    """
    for key, value in list(json_file.items()):
        if key == "period":
            del json_file[key]
        elif isinstance(value, dict):
            remove_period_from_json(value)
    return json_file


def run_pktvisor_container(container_image, port=10853, role="user", container_name=PKTVISOR_CONTAINER_NAME):
    """
    Run a pktvisor container

    :param (str) container_image: that will be used for running the container
    :param (str) port: Port on which the web service must be run [default: 10853]
    :param (str) role: that manage the permissions. [Default: 'user']
    :param (str) container_name: base of container name
    :returns: (str) the container ID
    """
    assert_that(role, any_of(equal_to('user'), equal_to('admin')), "Unexpect permission role")
    PKTVISOR_CONTAINER_NAME = container_name + random_string(3)
    client = docker.from_env()
    iface = configs.get('iface', 'dummy0')
    pkt_command = ["pktvisord", iface]
    if port != 10853:
        pkt_command.insert(-1, '-p')
        pkt_command.insert(-1, str(port))
    if role == "admin":
        pkt_command.insert(-1, '--admin-api')
    container = client.containers.run(container_image, name=PKTVISOR_CONTAINER_NAME, detach=True,
                                      network_mode='host', command=pkt_command)
    return container.id


@threading_wait_until
def check_amount_of_pkt_with_status(amount_of_pktvisor, pkt_status, event=None):
    docker_client = docker.from_env()
    containers = docker_client.containers.list(all=True)
    containers_with_expected_status = list()
    for container in containers:
        is_test_container = container.name.startswith(PKTVISOR_CONTAINER_NAME)
        if is_test_container is True:
            status = container.status
            if status == pkt_status:
                containers_with_expected_status.append(container)
            if len(set(containers_with_expected_status)) == int(amount_of_pktvisor):
                event.set()
                return containers_with_expected_status
    return containers_with_expected_status
