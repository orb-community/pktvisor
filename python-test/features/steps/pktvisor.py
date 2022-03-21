from utils import random_string
import docker
from behave import step
from hamcrest import *
import requests
from retry import retry

PKTVISOR_CONTAINER_NAME = "pktvisor-test"


def run_pktvisor_container(container_image, port="default", container_name=PKTVISOR_CONTAINER_NAME):
    """
    Run a pktvisor container

    :param (str) container_image: that will be used for running the container
    :param (str) port: Port on which the web service must be run [default: 10853]
    :param (dict) env_vars: that will be passed to the container context
    :param (str) container_name: base of container name
    :returns: (str) the container ID
    """
    PKTVISOR_CONTAINER_NAME = container_name + random_string(3)
    client = docker.from_env()
    pkt_command = ["pktvisord", "wlo1"]
    if port != "default":
        pkt_command.insert(-1, '-p')
        pkt_command.insert(-1, port)
    container = client.containers.run(container_image, name=PKTVISOR_CONTAINER_NAME, detach=True,
                                      network_mode='host', command=pkt_command)
    return container.id



@step("run pktvisor on port {pkt_port}")
def run_pktvisor(context, pkt_port):
    context.pkt_port = pkt_port
    context.container_id = run_pktvisor_container("ns1labs/pktvisor", pkt_port)


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
@retry(tries=5, delay=0.2)
def check_amount_of_pkt_with_status(context, amount_of_pktvisor, pkt_status):
    docker_client = docker.from_env()
    containers = docker_client.containers.list(all=True)
    containers_with_expected_status = list()
    for container in containers:
        is_test_container = container.name.startswith(PKTVISOR_CONTAINER_NAME)
        if is_test_container is True:
            status = container.status
            if status == pkt_status:
                containers_with_expected_status.append(container)
    assert_that(len(set(containers_with_expected_status)), equal_to(int(amount_of_pktvisor)),
                f"Amount of pktvisor container with referred status failed")


@step("pktvisor API must be enabled")
def check_pkt_base_API(context):
    if context.pkt_port == "default":
        context.pkt_port = 10853

    pkt_api_get_endpoints = ['metrics/app',
                             'metrics/bucket/0',
                             'metrics/window/2',
                             'metrics/window/3',
                             'metrics/window/4',
                             'metrics/window/5',
                             'taps',
                             'policies',
                             'policies/__all/metrics/window/2',
                             'policies/__all/metrics/window/3',
                             'policies/__all/metrics/window/4',
                             'policies/__all/metrics/window/5',
                             'policies/__all/metrics/prometheus']
    for endpoint in pkt_api_get_endpoints:
        make_get_request(endpoint, context.pkt_port)


@retry(tries=3, delay=1)
def make_get_request(end_point, pkt_port=10853, expected_status_code=200):
    pkt_base_api = 'http://localhost:'+str(pkt_port)+'/api/v1/'
    path = pkt_base_api+end_point
    response = requests.get(path)
    assert_that(response.status_code, equal_to(int(expected_status_code)),
                f"Get request to endpoint {path} failed with status {response.status_code}")
    return response
