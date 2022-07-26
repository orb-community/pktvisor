# -*- coding: utf-8 -*-
"""
/*
* BehaveX - Agile test wrapper on top of Behave (BDD)
*/

Test report utility methods for retrieving summarized test execution information
 from features and scenarios
"""
# pylint: disable=W0703
# pylint: disable=W0703 , E1101

# __future__ is added in order to maintain compatibility
from __future__ import absolute_import, print_function

import codecs
import hashlib
import os
import re
import shutil
import string
import sys
import traceback
import unicodedata
from operator import getitem

from behave.model_core import Status

from behavex.conf_mgr import get_env, get_param, set_env
from behavex.global_vars import global_vars


def gather_steps_with_definition(features, steps_definition):
    all_steps = []
    for feature in features:
        for scenario in feature['scenarios']:
            all_steps += scenario['steps']
            if scenario['background']:
                all_steps += scenario['background']['steps']
    result = {}
    if steps_definition:
        for id_hash, definition in steps_definition.items():
            result[definition] = {'steps': []}
            for step in all_steps:
                if step['hash'] == int(id_hash):
                    result[definition]['steps'].append(step)
        for definition, value in result.items():
            result[definition] = get_summary_definition(value['steps'])

    return result


def get_summary_definition(steps):
    result = {'steps': {}, 'status': []}
    for step in steps:
        result['status'].append(step['status'])
        execution = 1 if step['status'] in ('failed', 'passed') else 0
        if step['name'] in result['steps']:
            result['steps'][step['name']]['executions'] += execution
            result['steps'][step['name']]['time'] += step['duration']
            result['steps'][step['name']]['status'].append(step['status'])
            result['steps'][step['name']]['appearances'] += 1
        else:
            result['steps'][step['name']] = {
                'executions': execution,
                'time': step['duration'],
                'status': [step['status']],
                'appearances': 1,
            }
    total_time = 0.0
    executions = 0
    appearances = 0
    any_status_failed = False
    any_status_passed = False
    for step_instanced in result['steps'].values():
        total_time += step_instanced['time']
        executions += step_instanced['executions']
        appearances += step_instanced['appearances']
        if 'passed' in step_instanced['status']:
            any_status_passed = True
        elif 'failed' in step_instanced['status']:
            any_status_failed = True
    if any_status_failed:
        result['overall_status'] = 'failed'
    elif any_status_passed:
        result['overall_status'] = 'passed'
    else:
        result['overall_status'] = 'skipped'
    if executions > 0:
        avg_time = total_time / executions
    else:
        avg_time = 0
    result['avg'] = avg_time
    result['time'] = total_time
    result['executions'] = executions
    result['appearances'] = appearances
    return result


def count_by_status(values, func='getitem'):
    if func == 'getitem':
        get_item = getitem
    elif func == 'getattr':
        get_item = getattr
    elif func == 'first_value':

        def get_item(x, y):
            return x

    else:
        get_item = func
    skipped = len(
        [
            1
            for value in values
            if get_item(value, 'status') in ('skipped', 'undefined', 'untested')
        ]
    )
    passed = len([1 for value in values if get_item(value, 'status') == 'passed'])
    failed = len([1 for value in values if get_item(value, 'status') == 'failed'])
    return passed, failed, skipped


def calculate_status(list_status):
    set_status = set(list_status)
    if 'untested' in set_status:
        set_status.remove('untested')
        set_status.add('skipped')
    if 'undefined' in set_status:
        set_status.remove('undefined')
        set_status.add('skipped')
    if 'failed' in set_status:
        return 'failed'
    elif {'skipped'} == set_status:
        return 'skipped'
    else:
        return 'passed'


def gather_steps(features):
    steps = {}
    for feature in features:
        for scenario in feature['scenarios']:
            steps_back = [step for step in scenario['background']['steps']]
            for step in scenario['steps'] + steps_back:
                if not step['name'] in steps:
                    steps[step['name']] = {
                        'quantity': 0,
                        'total_duration': 0,
                        'appearances': 0,
                        'passed': 0,
                        'failed': 0,
                        'skipped': 0,
                    }
                steps[step['name']]['appearances'] += 1

                add = (
                    0
                    if step['status'].lower() in ['skipped', 'untested', 'undefined']
                    else 1
                )
                passed = 1 if step['status'] == 'passed' else 0
                failed = 1 if step['status'] == 'failed' else 0
                steps[step['name']]['passed'] += passed
                steps[step['name']]['failed'] += failed
                steps[step['name']]['quantity'] += add
                steps[step['name']]['skipped'] += not add
                steps[step['name']]['total_duration'] += step['duration']

    return steps


def gather_errors(scenario, retrieve_step_name=False):
    if retrieve_step_name:
        return scenario['error_msg'], scenario['error_lines'], scenario['error_step']
    else:
        return scenario['error_msg'], scenario['error_lines']


def pretty_print_time(seconds_float, sec_decimals=1):
    seconds_float = round(seconds_float, sec_decimals)
    minutes, seconds = divmod(seconds_float, 60)
    hours, minutes = divmod(minutes, 60)

    seconds = (
        int(seconds) if float(seconds).is_integer() else round(seconds, sec_decimals)
    )

    def _pretty_format(cant, unit):
        return '{}{}'.format(cant, unit) if cant > 0 else ''

    time_string = '{} {} {}'.format(
        _pretty_format(int(hours), 'h'),
        _pretty_format(int(minutes), 'm'),
        _pretty_format(seconds, 's'),
    )
    time_string = '0s' if time_string.strip() == '' else time_string
    return time_string


def normalize_path(path):
    exp = re.compile('\\\\|/')
    return os.path.join(*exp.split(path))


def resolving_type(step, scenario, background=True):
    if step['index'] == 0:
        return step['step_type'].title()
    else:
        steps = scenario['steps']
        if 'background' in list(step.keys()) and not background:
            steps = scenario['background']['steps']
        # noinspection PyBroadException
        try:
            previous_type = steps[step['index'] - 1]['step_type']
        except BaseException:
            previous_type = step['step_type']
        if previous_type == step['step_type']:
            return 'And'
        else:
            return step['step_type'].title()


def try_operate_descriptor(dest_path, execution, return_value=False):
    passed = False
    following = True
    retry_number = 1
    while not passed and following:
        try:
            result = execution()
            passed = True
            if return_value:
                return result
        except Exception as exception:
            menu = (
                '\nAnother program is using the files in path {}. '
                "Please, close the program and press 'c' to continue "
                " or 'a' for abort. Retry number {}\n\n.{}"
            )
            option_correct = False
            retry_number += 1
            option = (
                str(
                    input(
                        menu.format(os.path.abspath(dest_path), retry_number, exception)
                    )
                )
                .upper()
                .strip()
            )
            while not option_correct and not passed:
                if option == 'C':
                    following = True
                    option_correct = True
                elif option == 'A':
                    exit()
                else:
                    following = True
                    option_correct = False
                    msg = (
                        "\nInvalid option. Please, press 'c' to continue "
                        "or 'a' to abort\n"
                    )
                    option = str(input(msg)).upper().strip()


def get_status(dictionary):
    return (
        dictionary.get('failed', False)
        or dictionary.get('passed', False)
        or dictionary.get('skipped', 'skipped')
    )


def get_test_execution_tags():
    if not get_env('behave_tags'):
        behave_tags_path = os.path.join(
            os.path.abspath(get_env('OUTPUT')), global_vars.behave_tags_file
        )
        behave_tags_file = open(behave_tags_path, 'r')
        behave_tags = behave_tags_file.readline().strip()
        behave_tags_file.close()
        os.chmod(behave_tags_path, 511)  # nosec
        set_env('behave_tags', behave_tags.replace('@MANUAL', 'False'))
        return get_env('behave_tags')
    else:
        return get_env('behave_tags')


def match_for_execution(tags):
    # Check filter
    tag_re = re.compile(r'@?[\w\d\-_.]+')
    tags_filter = get_test_execution_tags()
    # Eliminate tags put for param dry-rFun
    if get_param('dry_run'):
        if 'BHX_MANUAL_DRY_RUN' in tags:
            tags.remove('BHX_MANUAL_DRY_RUN')
            tags.remove('MANUAL')
    # Set scenario tags in filter
    for tag in tags:
        # Try with and without @
        def replace(arroba, x, y):
            return re.sub(r'^{}{}$'.format(arroba, x), 'True', y)

        tags_filter = ' '.join(
            [replace('@', tag, tag_) for tag_ in tags_filter.split()]
        )

        tags_filter = ' '.join([replace('', tag, tag_) for tag_ in tags_filter.split()])

    # Set all other tags to False
    for tag in tag_re.findall(tags_filter):
        if tag not in ('not', 'and', 'or', 'True', 'False'):
            tags_filter = tags_filter.replace(tag + ' ', 'False ')
    return tags_filter == '' or eval(tags_filter)


def copy_bootstrap_html_generator(output):
    dest_path = os.path.join(output, 'outputs', 'bootstrap')
    bootstrap_path = ['outputs', 'bootstrap']
    bootstrap_path = os.path.join(global_vars.execution_path, *bootstrap_path)
    if os.path.exists(dest_path):
        try_operate_descriptor(dest_path, lambda: shutil.rmtree(dest_path))
    try_operate_descriptor(
        dest_path, lambda: shutil.copytree(bootstrap_path, dest_path)
    )


def get_overall_status(output):
    if not output:
        return {'status': 'skipped'}
    overall_status = {
        feature['status']: feature['status'] for feature in output['features']
    }
    overall_status_end = get_status(overall_status)
    return overall_status_end


def get_save_function(path, content):
    def fun_save():
        with codecs.open(path, 'w', 'utf8') as file_:
            file_.write(content)
        os.chmod(path, 511)  # nosec

    return fun_save


def create_log_path(name, execution_retry=False):
    name = get_string_hash(name)
    if sys.version_info < (3, 0):
        path = os.path.join(get_env('logs').decode('utf8'), str(name))
    else:
        path = os.path.join(get_env('logs'), str(name))
    initial_path = path
    scenario_outline_index = 1
    while os.path.exists(path):
        if execution_retry:
            return path
        path = initial_path + u'_' + str(scenario_outline_index)
        scenario_outline_index += 1
    os.makedirs(path)
    return path


def get_error_message(message_error):
    if not message_error:
        return u''
    if isinstance(message_error, Exception):
        if hasattr(message_error, 'message'):
            # noinspection PyBroadException
            try:
                message_error = traceback.format_tb(message_error.message)
            except BaseException:
                message_error = repr(message_error.message)
        if hasattr(message_error, 'exc_traceback'):
            message_error = traceback.format_tb(message_error.exc_traceback)
    elif not isinstance(message_error, str):
        message_error = repr(message_error)
    return u'\n'.join(
        [16 * u' ' + line for line in text(message_error).split('\n')]
    ).strip()


def text(value, encoding=None, errors=None):
    if value:
        value = value.name if isinstance(value, Status) else value.replace('\\', '/')
    if encoding is None:
        encoding = 'unicode-escape'
    if errors is None:
        errors = 'replace'

    if isinstance(value, str):
        # -- PASS-THROUGH UNICODE (efficiency):
        return value
    elif isinstance(value, bytes):
        return str(value, encoding, errors)
    elif isinstance(value, bytes):
        # -- MAYBE: filename, path, etc.
        try:
            return value.decode(sys.getfilesystemencoding())
        except UnicodeError:
            return value.decode('utf-8', 'replace')
    else:
        # -- CONVERT OBJECT TO TEXT:
        try:
            output_text = str(value)
        except UnicodeError as e:
            output_text = str(e)
        return output_text


def get_string_hash(string_to_hash):
    return str(hashlib.sha256(string_to_hash.encode('UTF-8')).hexdigest())


def normalize_filename(input_name):
    valid_name = None
    try:
        if sys.version_info[0] == 2:
            if isinstance(input_name, str):
                if isinstance(input_name, str):
                    input_name = text(input_name)
            else:
                raise TypeError
            if not input_name:
                return u''
            # xrange has been replaced for range
            characters = ''.join(map(chr, range(255)))
            reserved_characters = '<>:\'"/\\|?*'
            for character in reserved_characters:
                characters = characters.replace(character, '')
            valid_name = ''.join(char for char in input_name if char in characters)
            valid_name = unicodedata.normalize('NFKD', valid_name).encode(
                'ascii', 'ignore'
            )
            valid_name = string.capwords(valid_name)
            valid_name = valid_name.replace(' ', '_')
            if isinstance(valid_name, str):
                valid_name = text(valid_name)
        if sys.version_info[0] == 3:
            if isinstance(input_name, str):
                pass
            else:
                raise TypeError
            characters = ''.join(chr(i) for i in range(255))
            reserved_characters = '<>:\'"/\\|?*'
            for character in reserved_characters:
                characters = characters.replace(character, '')
            valid_name = ''.join(char for char in input_name if char in characters)
            valid_name = unicodedata.normalize('NFKD', valid_name).encode(
                'ascii', 'ignore'
            )
            if isinstance(valid_name, str):
                valid_name = string.capwords(valid_name)
            else:
                valid_name = bytes.title(valid_name)
            if isinstance(valid_name, str):
                valid_name = valid_name.replace(' ', '_')
            else:
                valid_name = valid_name.replace(b' ', b'_')
            if isinstance(valid_name, str):
                valid_name = bytes(valid_name, encoding='UTF-8')
        if isinstance(valid_name, bytes):
            valid_name = valid_name.decode('utf8')
        return valid_name
    except TypeError:
        err_msg = 'Input should be str or unicode, but received a: {}'.format(
            type(input_name)
        )
        print(err_msg)
        return
