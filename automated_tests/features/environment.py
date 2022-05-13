import docker
from steps import test_config


PKTVISOR_CONTAINER_NAME = "pktvisor-test"


def before_scenario(context, scenario):
    cleanup_container(PKTVISOR_CONTAINER_NAME)
    test_config.send_terminal_commands("modprobe -v dummy numdummies=1", sudo=True)
    test_config.send_terminal_commands("ip link set dummy0 up", sudo=True)


def after_scenario(context, scenario):
    cleanup_container(PKTVISOR_CONTAINER_NAME)
    test_config.send_terminal_commands("rmmod dummy", sudo=True)


def cleanup_container(name_prefix):
    docker_client = docker.from_env()
    containers = docker_client.containers.list(all=True)
    for container in containers:
        test_container = container.name.startswith(name_prefix)
        if test_container is True:
            container.stop()
            container.remove()
