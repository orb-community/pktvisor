import docker
from steps import test_config


PKTVISOR_CONTAINER_NAME = "pktvisor-test"


def before_scenario(context, scenario):
    context.containers_id = dict()
    test_config.send_terminal_commands("modprobe -v dummy numdummies=1", sudo=True)
    test_config.send_terminal_commands("ip link set dummy0 up", sudo=True)


def after_scenario(context, scenario):
    cleanup_container(PKTVISOR_CONTAINER_NAME, context.containers_id.keys())


def cleanup_container(name_prefix, containers_id):
    docker_client = docker.from_env()
    for container_id in containers_id:
        container = docker_client.containers.get(container_id)
        container.stop()
        container.remove()
