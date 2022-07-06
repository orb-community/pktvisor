import random
import string
from json import loads, JSONDecodeError
import threading
from datetime import datetime
from hamcrest import *
import socket
import requests
import multiprocessing


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


def check_port_is_available(containers_id, available=True, time_to_wait=5):

    """
    :param (dict) containers_id: dictionary in which the keys are the ids of the containers and the values are the ports
    on which the containers are running
    :param (bool) available: Status of the port on which agent must try to run. Default: available.
    :param (int) time_to_wait: seconds that threading must wait after run the agent
    :return: (int) port number
    """

    assert_that(available, any_of(equal_to(True), equal_to(False)), "Unexpected value for 'available' parameter")
    process = multiprocessing.current_process()
    if process.name != "MainProcess":
        process_number = int(format(int(process.name.split("-")[-1]), "e").split(".")[0])
        threading.Event().wait(process_number)
    if not available:
        unavailable_port = list(containers_id.values())[-1]
        return unavailable_port
    else:
        available_port = None
        retries = 0
        while available_port is None and retries < 10:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', 0))
            addr = s.getsockname()
            s.close()
            retries += 1
            if addr[1] not in list(containers_id.values()):
                available_port = addr[1]
                return available_port
    assert_that(available_port, is_not(None), "Unable to find an available port to run orb agent")
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
