import docker


PKTVISOR_CONTAINER_NAME = "pktvisor-test"


def before_scenario(context, scenario):
    cleanup_container(PKTVISOR_CONTAINER_NAME)


def after_feature(context, feature):
    cleanup_container()


def cleanup_container(name_prefix):
    docker_client = docker.from_env()
    containers = docker_client.containers.list(all=True)
    for container in containers:
        test_container = container.name.startswith(name_prefix)
        if test_container is True:
            container.stop()
            container.remove()
