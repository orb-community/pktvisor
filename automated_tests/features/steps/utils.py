import random
import string
from json import loads, JSONDecodeError
import threading
from datetime import datetime
from hamcrest import *
import socket
import requests


def random_string(k=10):
    """
    Generates a string composed of of k (int) random letters lowercase and uppercase mixed

    :param (int) k: sets the length of the randomly generated string
    :return: (str) string consisting of k random letters lowercase and uppercase mixed. Default:10
    """
    return ''.join(random.choices(string.ascii_letters, k=k))


def safe_load_json(json_str):
    """
    Safely parses a string into a JSON object, without ever raising an error.
    :param (str) json_str: to be loaded
    :return: the JSON object, or None if string is not a valid JSON.
    """

    try:
        return loads(json_str)
    except JSONDecodeError:
        return None


def check_logs_contain_message_and_name(logs, expected_message, name, name_key):
    """
    Gets the logs from Orb agent container

    :param (list) logs: list of log lines
    :param (str) expected_message: message that we expect to find in the logs
    :param (str) name: element name that we expect to find in the logs
    :param (str) name_key: key to get element name on log line
    :returns: (bool) whether expected message was found in the logs
    """

    for log_line in logs:
        log_line = safe_load_json(log_line)

        if log_line is not None and log_line['msg'] == expected_message:
            if log_line is not None and log_line[name_key] == name:
                return True, log_line

    return False, "Logs doesn't contain the message and name expected"


def remove_empty_from_json(json_file):
    """
    Delete keys with the value "None" in a dictionary, recursively.

    """
    for key, value in list(json_file.items()):
        if value is None:
            del json_file[key]
        elif isinstance(value, dict):
            remove_empty_from_json(value)
    return json_file


def threading_wait_until(func):
    def wait_event(*args, wait_time=0.5, timeout=10, start_func_value=False, **kwargs):
        event = threading.Event()
        func_value = start_func_value
        start = datetime.now().timestamp()
        time_running = 0
        while not event.is_set() and time_running < int(timeout):
            func_value = func(*args, event=event, **kwargs)
            event.wait(wait_time)
            time_running = datetime.now().timestamp() - start
        return func_value

    return wait_event


def check_port_is_available(availability=True):
    """

    :param (str) availability: Status of the port on which pktvisor must try to run. Default: available.
    :return: (int) port number
    """
    assert_that(availability, any_of(equal_to(True), equal_to(False)), "Unexpected value for availability")
    available_port = None
    port_options = range(10853, 10900)
    for port in port_options:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result == 0:
            available_port = port
            if availability is True:
                continue
            else:
                return available_port
        else:
            available_port = port
            break
    assert_that(available_port, is_not(equal_to(None)), "No available ports to bind")
    return available_port


@threading_wait_until
def make_get_request(end_point, pkt_port=10853, expected_status_code=200, event=None):
    """

    :param end_point: endpoint to which the request must be sent
    :param pkt_port: port on which pktvisor is running
    :param expected_status_code: expected status from response
    :param event: threading.event
    :return: response
    """
    pkt_base_api = 'http://localhost:' + str(pkt_port) + '/api/v1/'
    path = pkt_base_api + end_point
    response = requests.get(path)
    if response.status_code == int(expected_status_code):
        event.set()
    assert_that(response.status_code, equal_to(int(expected_status_code)),
                f"Get request to endpoint {path} failed with status {response.status_code}")
    return response
