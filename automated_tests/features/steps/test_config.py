import configparser
from hamcrest import *
import shlex
import subprocess
import re


class TestConfig:
    _configs = None

    def __init__(self):
        raise RuntimeError('Call instance() instead')

    @classmethod
    def configs(cls):
        if cls._configs is None:
            cls._configs = _read_configs()
        return cls._configs


def _read_configs():
    parser = configparser.ConfigParser()
    parser.read('test_config.ini')
    configs = parser['test_config']

    assert_that(configs.get('sudo_password'), not_none(), 'Sudo password was not provided!')
    return configs


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
        configs = TestConfig.configs()
        sudo_password = configs.get('sudo_password')
        p = subprocess.Popen(['sudo', '-S'] + args, stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE, universal_newlines=True)
        subprocess_return_terminal = p.communicate(sudo_password + '\n')
    return subprocess_return_terminal
