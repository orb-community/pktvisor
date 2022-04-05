from utils import random_string
import docker
from behave import step
from hamcrest import *
import requests
import yaml
from yaml.loader import SafeLoader
from retry import retry
import random
from policies import *

PKTVISOR_CONTAINER_NAME = "pktvisor-test"


@step("run pktvisor instance on port {pkt_port} with {role} permission")
def run_pktvisor(context, pkt_port, role):
    if pkt_port.isdigit() is False and pkt_port.lower() == "default":
        context.pkt_port = 10853
    elif pkt_port.isdigit() is True:
        context.pkt_port = int(pkt_port)
    context.container_id = run_pktvisor_container("ns1labs/pktvisor", pkt_port, role)


@step("that a pktvisor instance is running on port {pkt_port} with {role} permission")
def pkt_running(context, pkt_port, role):
    run_pktvisor(context, pkt_port, role)


@step("{amount_of_policies} policies {status_condition} be running")
def amount_of_policies_per_status(context, amount_of_policies, status_condition):
    assert_that(status_condition, any_of(equal_to("must"), equal_to("must not")),
                'Unexpect condition for policy status')
    status_condition_dict = {"must": True, "must not": False}
    all_policies = make_get_request('policies', context.pkt_port).json()
    amount_of_policies_per_status = list()
    for key, value in all_policies.items():
        if value['input'][list(value['input'].keys())[0]]['input']['running'] is status_condition_dict[
            status_condition]:
            amount_of_policies_per_status.append(key)
    assert_that(len(amount_of_policies_per_status), equal_to(int(amount_of_policies)),
                f"Unexpect amount of policies that {status_condition} be running")


@step("create a new policy with {handler} handler(s)")
def create_new_policy(context, handler, **kwargs):
    policy_yaml = policies.generate_policy(handler, random_string(10))
    policy_yaml_parsed = yaml.load(policy_yaml, Loader=SafeLoader)
    yaml_policy_data = yaml.dump(policy_yaml_parsed)
    if "pkt_port" and "expected_status_code" in kwargs:
        context.response = create_policy(yaml_policy_data, kwargs["pkt_port"], kwargs["expected_status_code"])
    elif "pkt_port" in kwargs:
        context.response = create_policy(yaml_policy_data, kwargs["pkt_port"])
    elif "expected_status_code" in kwargs:
        context.response = create_policy(yaml_policy_data, context.pkt_port, kwargs["expected_status_code"])
    else:
        context.response = create_policy(yaml_policy_data, context.pkt_port)


@step("try to create a new policy with {handler} handler(s)")
def try_to_create_new_policy(context, handler):
    create_new_policy(context, handler, pkt_port=context.pkt_port, expected_status_code=404)


@step("status code returned on response must be {status_code}")
def check_response_status_code(context, status_code):
    assert_that(context.response.status_code, equal_to(int(status_code)), "Wrong status code on response")


@step("delete {amount_of_policies} policies")
def remove_policies(context, amount_of_policies):
    names_of_all_policies = make_get_request('policies', context.pkt_port).json().keys()
    policies_to_remove = random.sample(names_of_all_policies, int(amount_of_policies))
    for policy in policies_to_remove:
        remove_policy(policy, context.pkt_port)
        response = get_policy(policy, 10853, 404)
        assert_that(response.json(), has_key('error'), "Unexpected message for non existing policy")
        assert_that(response.json(), has_value('policy does not exists'), "Unexpected message for non existing policy")


@step("try to delete a policy")
def try_to_delete_policies(context):
    names_of_all_policies = make_get_request('policies', context.pkt_port).json().keys()
    sample_policy = random.sample(names_of_all_policies, 1)[0]
    context.response = remove_policy(sample_policy, context.pkt_port, 404)


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
def create_policy(yaml_data, pkt_port=10853, expected_status_code=201):
    """

    :param yaml_data: policy configurations
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :return: response
    """
    pkt_api = 'http://localhost:' + str(pkt_port) + '/api/v1/policies'
    headers_request = {'Content-type': 'application/x-yaml'}
    response = requests.post(pkt_api, data=yaml_data, headers=headers_request)
    assert_that(response.status_code, equal_to(int(expected_status_code)),
                f"Post request to create a policy failed with status {response.status_code}")
    return response


@retry(tries=3, delay=1)
def make_get_request(end_point, pkt_port=10853, expected_status_code=200):
    """

    :param end_point: endpoint to which the request must be sent
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :return: response
    """
    pkt_base_api = 'http://localhost:' + str(pkt_port) + '/api/v1/'
    path = pkt_base_api + end_point
    response = requests.get(path)
    assert_that(response.status_code, equal_to(int(expected_status_code)),
                f"Get request to endpoint {path} failed with status {response.status_code}")
    return response


def run_pktvisor_container(container_image, port="default", role="user", container_name=PKTVISOR_CONTAINER_NAME):
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
    pkt_command = ["pktvisord", "wlo1"]
    if port != "default":
        pkt_command.insert(-1, '-p')
        pkt_command.insert(-1, port)
    if role == "admin":
        pkt_command.insert(-1, '--admin-api')
    container = client.containers.run(container_image, name=PKTVISOR_CONTAINER_NAME, detach=True,
                                      network_mode='host', command=pkt_command)
    return container.id


def get_policy(policy_name, pkt_port=10853, expected_status_code=200):
    """

    :param (str) policy_name: name of the policy to be fetched
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :return: (dict) referred policy data
    """
    endpoint = f"policies/{policy_name}"
    return make_get_request(endpoint, pkt_port, expected_status_code)


def remove_policy(policy_name, pkt_port=10853, expected_status_code=204):

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
