import docker
from steps import test_config
from steps import utils


PKTVISOR_CONTAINER_NAME = "pktvisor-test"
sudo = test_config.TestConfig.configs().get("sudo")


def before_scenario(context, scenario):
    context.containers_id = dict()
    context.mock_iface_name = utils.random_string(10)
    test_config.send_terminal_commands(f"ip link add {context.mock_iface_name} type dummy", sudo=sudo)
    test_config.send_terminal_commands(f"ip link set {context.mock_iface_name} up", sudo=sudo)


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
