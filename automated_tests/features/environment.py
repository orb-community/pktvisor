import docker
from steps import test_config
from steps import utils
from hamcrest import *


PKTVISOR_CONTAINER_NAME = "pktvisor-test"
sudo = test_config.TestConfig.configs().get("sudo")


def before_scenario(context, scenario):
    context.containers_id = dict()
    context.mock_iface_name = utils.random_string(10)
    add_return = test_config.send_terminal_commands(f"ip link add {context.mock_iface_name} type dummy", sudo=sudo)
    set_return = test_config.send_terminal_commands(f"ip link set {context.mock_iface_name} up", sudo=sudo)
    assert_that(add_return[1], not_(contains_string("Operation not permitted")), "Unable to add dummy iface")
    assert_that(set_return, equal_to(('', '')), "Unable to up dummy iface")


def after_scenario(context, scenario):
    cleanup_container(context.containers_id.keys())
    test_config.send_terminal_commands(f"ip link set {context.mock_iface_name} down", sudo=sudo)
    test_config.send_terminal_commands(f"ip link delete {context.mock_iface_name} type dummy", sudo=sudo)


def cleanup_container(containers_id):
    docker_client = docker.from_env()
    for container_id in containers_id:
        container = docker_client.containers.get(container_id)
        container.stop()
        container.remove()
