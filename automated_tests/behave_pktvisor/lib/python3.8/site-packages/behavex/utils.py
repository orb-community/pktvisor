# -*- coding: utf-8 -*-
"""
/*
* BehaveX - Agile test wrapper on top of Behave (BDD)
*/
"""
# __future__ added for compatibility
from __future__ import absolute_import, print_function

import codecs
import functools
import json
import logging
import multiprocessing
import os
import re
import shutil
import sys
from functools import reduce
from tempfile import gettempdir

from behave.model import ScenarioOutline
from behave.parser import parse_feature, parse_file
from configobj import ConfigObj

from behavex.conf_mgr import get_env, get_param, set_env
from behavex.execution_singleton import ExecutionSingleton
from behavex.global_vars import global_vars
from behavex.outputs import report_html
from behavex.outputs.output_strings import TEXTS
from behavex.outputs.report_utils import (
    get_save_function,
    match_for_execution,
    normalize_filename,
    get_string_hash,
    try_operate_descriptor,
)

LOGGING_CFG = ConfigObj(os.path.join(global_vars.execution_path, 'conf_logging.cfg'))
LOGGING_LEVELS = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
}


def append_results(codes, json_reports, tuple_values):
    codes.append(tuple_values[0])
    json_reports.append(tuple_values[1])


def create_partial_function_append(codes, json_reports):
    return functools.partial(append_results, codes, json_reports)


def get_logging_level():
    if get_param('logging_level'):
        log_level = get_param('logging_level')
    else:
        log_level = LOGGING_CFG['logger_root']['level']
        log_level = LOGGING_LEVELS.get(log_level.lower(), logging.DEBUG)
    return log_level


# noinspection PyDictCreation
def join_feature_reports(json_reports):
    scenario_lines = get_env('scenario_lines')
    if len(json_reports) == 1:
        merged_json = json_reports[0]
    else:
        merged_json = {}
        merged_json['environment'] = join_list_dict(json_reports, 'environment')
        merged_json['steps_definition'] = join_step_definitions(json_reports)
        merged_json['features'] = sum((json_['features'] for json_ in json_reports), [])
    if IncludeNameMatch().bool() or IncludePathsMatch().bool() or MatchInclude().bool():
        delete = []
        for index, feature in enumerate(merged_json['features'][:]):
            lines = scenario_lines.get(feature['filename'], {})
            scenarios = [
                scenario
                for scenario in feature['scenarios']
                if IncludeNameMatch()(scenario['name'])
                and MatchInclude()(feature['filename'])
                and IncludePathsMatch()(
                    scenario['filename'], lines.get(scenario['name'], -1)
                )
            ]
            if not scenarios:
                # create index list for delete after iterated the feature list.
                delete.append(index - len(delete))
            else:
                merged_json['features'][index]['scenarios'] = scenarios
        if delete:
            for index in delete:
                del merged_json['features'][index]
    return merged_json


def join_list_dict(json_reports, key):
    new_list_dict = sum(
        (json_[key] for json_ in json_reports if isinstance(json_[key], dict)), []
    )
    return new_list_dict


def join_step_definitions(json_reports):
    # the update function forced to return a list
    def update(x, y):
        if isinstance(x, dict) and isinstance(y, dict):
            return dict(list(x.items()) + list(y.items()))
        elif isinstance(x, dict) and not isinstance(y, dict):
            return dict(list(x.items()))
        elif isinstance(y, dict) and not isinstance(x, dict):
            return dict(list(y.items()))
        else:
            return {}

    list_definitions = [_json['steps_definition'] for _json in json_reports]

    return {} if not list_definitions else reduce(update, list_definitions)


# the join_scenario_reports function forced to return a list


def join_scenario_reports(json_reports):
    result = {}
    status = {}
    for json_ in json_reports:
        if not json_['features']:
            continue
        filename = json_['features'][0]['filename']
        duration = 0
        if filename not in result:
            status[filename] = [json_['features'][0]['status']]
            result[filename] = json_
            result[filename]['features'][0]['scenarios'] = json_['features'][0][
                'scenarios'
            ]
        else:
            duration = result[filename]['features'][0]['duration']
            result[filename]['features'][0]['scenarios'].extend(
                json_['features'][0]['scenarios']
            )
            status[filename].append(json_['features'][0]['status'])
        for scenario in json_['features'][0]['scenarios']:
            duration += round(scenario['duration'], 1)
        result[filename]['features'][0]['duration'] = duration

    for feature, status_ in status.items():
        skipped = all(st == 'skipped' for st in status_)
        failed = any(st == 'failed' for st in status_)
        result[feature]['features'][0]['status'] = (
            'skipped' if skipped else 'failed' if failed else 'passed'
        )
    return list(result.values())


def explore_features(features_path, features_list=None):
    if features_list is None:
        features_list = []
    for node in os.listdir(features_path):
        if os.path.isdir(os.path.join(features_path, node)):
            explore_features(os.path.join(features_path, node), features_list)
        else:
            if node.endswith('.feature'):
                path_feature = os.path.abspath(os.path.join(features_path, node))
                feature = should_be_run(path_feature)
                if feature:
                    features_list.append(feature)
    return features_list


def should_be_run(path_feature):
    feature = parse_file(path_feature)
    if not feature:
        tags_list = []
    else:
        tags_list = [
            scenario.tags
            for scenario in feature.scenarios
            if hasattr(feature, 'scenarios')
        ]
        tags_list.append(feature.tags)
    match_tag = any(match_for_execution(tags) for tags in tags_list)

    filename = feature.filename
    if (
        match_tag
        and MatchInclude()(filename)
        and match_any_paths(feature)
        and match_any_name(feature)
    ):
        return feature
    else:
        return False


def match_any_paths(feature):
    result = False
    for scenario in feature.scenarios:
        if hasattr(scenario, 'scenarios'):
            for outline in scenario.scenarios:
                if IncludePathsMatch()(outline.filename, outline.line):
                    return True
        else:
            if IncludePathsMatch()(feature.filename, scenario.line):
                return True
    return result


def match_any_name(feature):
    if not IncludeNameMatch().bool():
        return True
    result = False
    for scenario in feature.scenarios:
        if hasattr(scenario, 'scenarios'):
            for outline in scenario.scenarios:
                if IncludeNameMatch()(outline.name):
                    return True
        else:
            if IncludeNameMatch()(scenario.name):
                return True
    return result


def copy_bootstrap_html_generator():
    destination_path = os.path.join(get_env('OUTPUT'), 'outputs', 'bootstrap')
    bootstrap_path = ['outputs', 'bootstrap']
    bootstrap_path = os.path.join(global_vars.execution_path, *bootstrap_path)
    if os.path.exists(destination_path):
        try_operate_descriptor(
            destination_path, lambda: shutil.rmtree(destination_path)
        )
    try_operate_descriptor(
        destination_path, lambda: shutil.copytree(bootstrap_path, destination_path)
    )


def cleanup_folders():
    # output folder
    output_folder = get_env('output')

    def execution():
        return shutil.rmtree(output_folder, ignore_errors=True)

    try_operate_descriptor(output_folder, execution)
    if not os.path.exists(output_folder):
        try_operate_descriptor(output_folder, lambda: os.makedirs(output_folder))
    # temp folder
    temp_folder = get_env('temp')

    def execution():
        return shutil.rmtree(temp_folder, ignore_errors=True)

    try_operate_descriptor(temp_folder, execution)
    if not os.path.exists(temp_folder):
        try_operate_descriptor(temp_folder, lambda: os.makedirs(temp_folder))

    # behave folder
    behave_folder = os.path.join(get_env('OUTPUT'), 'behave')

    def execution():
        return shutil.rmtree(behave_folder, ignore_errors=True)

    try_operate_descriptor(behave_folder, execution)
    if not os.path.exists(behave_folder):
        try_operate_descriptor(behave_folder, lambda: os.makedirs(behave_folder))


def set_env_variable(key, value):
    if value:
        os.environ[key] = str(value)
        set_env(key.lower(), value)


def print_env_variables(keys):
    key_length = 20
    value_length = 60
    print('|{}| {}|'.format(''.ljust(key_length, '-'), ''.ljust(value_length, '-')))
    print(
        '|{}| {}|'.format(
            'ENV. VARIABLE'.ljust(key_length), 'VALUE'.ljust(value_length)
        )
    )
    print('|{}| {}|'.format(''.ljust(key_length, '-'), ''.ljust(value_length, '-')))
    for key in keys:
        print(
            '|{}| {}|'.format(
                key.upper().ljust(key_length),
                str(os.environ.get(key)).ljust(value_length),
            )
        )
    print('|{}| {}|'.format(''.ljust(key_length, '-'), ''.ljust(value_length, '-')))


def set_environ_config(args_parsed):
    global CONFIG
    global CONFIG_PATH
    CONFIG_PATH = None
    CONFIG = None

    if args_parsed.config:
        CONFIG_PATH = args_parsed.config
    if CONFIG_PATH is None:
        fwk_path = os.environ.get('BEHAVEX_PATH')
        CONFIG_PATH = os.path.join(fwk_path, 'conf_behavex.cfg')
    set_env_variable('CONFIG', CONFIG_PATH)


def print_parallel(msg, *args, **kwargs):
    logger = logging.getLogger('bhx_parallel')
    if len(logger.handlers) == 0:
        console_log = logging.StreamHandler(sys.stdout)
        console_log.setLevel(get_logging_level())
        logger.addHandler(console_log)
    if 'no_chain' in kwargs:
        logger.info(msg)
    else:
        logger.info(get_text(msg).format(*args))


def get_text(key_chain):
    dictionary = TEXTS
    keys = key_chain.split('.')
    result = None
    for i, key in enumerate(keys):
        msg = u'the key "{}" not found'.format(u'.'.join(keys[0 : i + 1]))
        result = dictionary.get(key, msg)
        if isinstance(result, str) or isinstance(result, str):
            return result
        if isinstance(result, dict):
            dictionary = result
        else:
            return u'key "{}" no found '.format(key_chain)
    if isinstance(result, dict):
        return u'key: "{}" is incomplete'.format(key_chain)


def configure_logging(args_parse):
    # Create log folder
    if not os.path.exists(get_env('logs')):
        os.makedirs(os.path.abspath(get_env('logs')))
    # get logging configuration

    logging_file = os.path.join(global_vars.execution_path, 'conf_logging.cfg')
    try:
        logging.config.fileConfig(logging_file)
    except Exception as logging_ex:
        print(logging_ex)
    if args_parse.parallel_processes > 1:
        logger = logging.getLogger()  # this gets the root logger
        lh_stdout = logger.handlers[0]  # stdout is the only handler initially
        # ... here I add my own handlers
        name = multiprocessing.current_process().name.split('-')[-1]
        path_stdout = os.path.join(gettempdir(), 'std{}2.txt'.format(name))
        if os.path.exists(path_stdout):
            try:
                os.remove(path_stdout)
            except Exception as remove_path_ex:
                print(remove_path_ex)

        file_stdout = open(path_stdout, 'w')  # example handler
        log_handler = logging.StreamHandler(file_stdout)
        logger.addHandler(log_handler)
        logger.removeHandler(lh_stdout)
        logger = logging.getLogger('parallel_behavex')
        console_log = logging.StreamHandler(sys.stdout)
        console_log.setLevel(get_logging_level())
        logger.addHandler(console_log)


def len_scenarios(feature_file):
    data = codecs.open(feature_file, encoding='utf8').read()
    feature = parse_feature(data=data)
    amount_scenarios = 0
    for scenario in feature.scenarios:
        if match_for_execution(scenario.tags):
            if isinstance(scenario, ScenarioOutline):
                outline_instances = 1
                for example in scenario.examples:
                    rows = len(example.table.rows)
                    if rows > outline_instances:
                        outline_instances = rows
                amount_scenarios += outline_instances
            else:
                amount_scenarios += 1
    return amount_scenarios


def check_environment_file():
    path_environment = os.path.join(os.environ.get('FEATURES_PATH'), 'environment.py')
    if not os.path.exists(path_environment):
        raise Exception("environment.py module not found in 'features' folder")


def set_behave_tags():
    behave_tags = os.path.join(get_env('OUTPUT'), 'behave', 'behave.tags')
    tags = []
    # Check for tags passed as arguments
    first_tag = True
    if get_env('tags'):
        for tag_param in get_env('tags').split(';'):
            tags_args = tag_param.split(',')
            if first_tag:
                first_tag = False
                tags.append('(')
            else:
                tags.append('and (')
            first_param_tag = True
            for tag in tags_args:
                if first_param_tag:
                    first_param_tag = False
                    tags.append(tag.strip())
                else:
                    tags.append('or ' + tag.strip())
            tags.append(')')
    tags_line = ' '.join(tags)
    tags_line = tags_line.replace('~', 'not ')
    tags_line = tags_line.replace(',', ' or ')
    try_operate_descriptor(
        behave_tags, execution=get_save_function(behave_tags, tags_line)
    )


def set_system_paths():
    input_path = os.pathsep + get_env('temp')
    os.environ['PATH'] += input_path


def generate_reports(json_output):
    report_html.generate_report(json_output)


def create_custom_log_when_called(self, key):
    if key == 'evidence_path':
        if not hasattr(self, 'log_path'):
            if not hasattr(self, 'scenario'):
                ex_msg = '"evidence_path" is only accessible in the context of a test scenario'
                raise Exception(ex_msg)
            self.log_path = get_string_hash(self.scenario.name)
        evidence_path = os.path.join(self.log_path, 'evidence')
        self.evidence_path = evidence_path
        try:
            os.makedirs(evidence_path, exist_ok=True)
        except OSError as error:
            print("It was not possible to create the folder to store additional scenario evidence...")
            raise error
        return evidence_path
    else:
        return object.__getattribute__(self, key)


def get_json_results():
    path_json = os.path.join(
        get_env('OUTPUT'), global_vars.report_filenames['report_json']
    )
    with open(path_json, 'r') as json_file:
        json_results = json.load(json_file)
    return json_results or {}


class MatchInclude(metaclass=ExecutionSingleton):
    def __init__(self, expr=None):
        if not expr:
            expr = get_param('include').replace("'", '"')
        self.features_path = os.path.abspath(os.environ.get('FEATURES_PATH'))
        expr = expr.replace(self.features_path, 'features').replace('\\', '\\\\')
        self.reg = re.compile(expr)

    def __call__(self, *args, **kwargs):
        return self.match(*args)

    def bool(self):
        return self.reg.pattern

    def match(self, filename):
        filename = os.path.abspath(filename)
        filename = 'features' + filename.replace(self.features_path, '')
        return not self.reg.match(filename) is None


class IncludePathsMatch(metaclass=ExecutionSingleton):
    def __init__(self, paths=None):
        if not paths:
            paths = get_env('include_paths', get_param('include_paths'))
        self.features_path = os.path.abspath(os.getenv('FEATURES_PATH'))
        self.include_paths = [
            os.path.abspath(path).replace(self.features_path, 'features')
            for path in paths
        ]
        self.features = [
            path
            for path in self.include_paths
            if not os.path.isdir(path) and ':' not in path
        ]
        self.scenarios = [
            path
            for path in self.include_paths
            if not os.path.isdir(path) and ':' in path
        ]
        self.folders = [path for path in paths if os.path.isdir(path)]

    def __call__(self, *args, **kwargs):
        return self.match(*args)

    def match(self, filename, scenario=None):
        if not self.include_paths:
            return True
        match_scenario, match_feature = False, False
        filename = os.path.abspath(filename).replace(self.features_path, 'features')
        if scenario:
            match_scenario = '{}:{}'.format(filename, scenario) in self.scenarios
        match_feature = filename in self.features
        return (
            match_scenario
            or match_feature
            or any(filename.startswith(folder) for folder in self.folders)
        )

    def bool(self):
        return self.include_paths and self.features and self.folders


class IncludeNameMatch(metaclass=ExecutionSingleton):
    def __init__(self, expr=None):
        if not expr:
            expr = get_param('name').replace("'", '"')
        self.reg = re.compile(expr)

    def __call__(self, *args, **kwargs):
        return self.match(*args)

    def bool(self):
        return self.reg.pattern

    def match(self, scenario):
        return not self.reg.match(scenario) is None


def get_autoretry_attempts(tags):
    pattern = '^AUTORETRY(_(\\d+))*$'
    attempts = 0
    for tag in tags:
        result = re.search(pattern, tag, re.IGNORECASE)
        if result:
            attempts_in_tag = result.group(2)
            attempts = int(attempts_in_tag) if attempts_in_tag else 2
    return attempts
