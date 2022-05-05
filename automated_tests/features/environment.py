import docker
import shlex
import subprocess
import re
from steps import test_config
from hamcrest import *


PKTVISOR_CONTAINER_NAME = "pktvisor-test"


def before_scenario(context, scenario):
    cleanup_container(PKTVISOR_CONTAINER_NAME)
    send_terminal_commands("modprobe -v dummy numdummies=1", sudo=True)
    send_terminal_commands("ip link set dummy0 up", sudo=True)


def after_scenario(context, feature):
    cleanup_container(PKTVISOR_CONTAINER_NAME)
    send_terminal_commands("rmmod dummy", sudo=True)


def cleanup_container(name_prefix):
    docker_client = docker.from_env()
    containers = docker_client.containers.list(all=True)
    for container in containers:
        test_container = container.name.startswith(name_prefix)
        if test_container is True:
            container.stop()
            container.remove()


def send_terminal_commands(command, separator=None, cwd_run=None, sudo=None):
    assert_that(sudo, any_of(equal_to(None), equal_to(True)), "Unexpected value for 'sudo' parameter")
    args = shlex.split(command)
    if sudo is None:
        available_machine = subprocess.Popen(
            args, stdout=subprocess.PIPE, cwd=cwd_run)
        subprocess_return = available_machine.stdout.read().decode()
        if separator == None:
            subprocess_return_terminal = subprocess_return.split()
        else:
            subprocess_return_terminal = re.split(separator, subprocess_return)
    else:
        configs = test_config.TestConfig.configs()
        sudo_password = configs.get('sudo_password')
        p = subprocess.Popen(['sudo', '-S'] + args, stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE, universal_newlines=True)
        subprocess_return_terminal = p.communicate(sudo_password + '\n')
    return subprocess_return_terminal



# #This will create a dummy interface in Linux
# sudo modprobe -v dummy numdummies=1
# sudo ip link set dummy0 up
#
# #run pktvisor over dummy0 interface
#
# #This will inject the pcap packets simulating a real flow
# sudo tcpreplay -i dummy0 -tK /home/lparente/git/pktvisor/src/tests/fixtures/dns_ipv6_udp.pcap
#
# # check pktvisor metrics
#
# #remove mod
# sudo rmmod dummy