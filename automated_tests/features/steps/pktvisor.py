from utils import random_string, threading_wait_until
import docker
from behave import step
from test_config import TestConfig
from utils import check_port_is_available, make_get_request
import threading
from hamcrest import *

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
def check_pkt_status(context, pkt_status):
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
