# -*- coding: utf-8 -*-

"""
/*
* BehaveX - Agile test wrapper on top of Behave (BDD)
*/

JSON test execution report.
"""

# pylint: disable=W0212
# Future added in order to maintain compatibility
from __future__ import absolute_import

import json
import multiprocessing
import os
import random
import traceback
from tempfile import gettempdir

from behave.step_registry import registry

from behavex.conf_mgr import get_env
from behavex.global_vars import global_vars
from behavex.outputs.report_utils import get_error_message, match_for_execution, text
from behavex.utils import try_operate_descriptor


def add_step_info(step, parent_node):
    index = len(parent_node)
    parent_node.append(_step_to_dict(index, step))


def add_step_info_background(step, parent_node):
    step_info = {}
    for attrib in ('step_type', 'name', 'text', 'status'):
        step_info[attrib] = text(getattr(step, attrib))
    step_info['duration'] = step.duration or 0
    if step.table:
        step_info['table'] = {}
        for heading in step.table.headings:
            step_info['table'][heading] = []
            for row in step.table:
                step_info['table'][heading].append(row[heading])
    step_info['index'] = len(parent_node)
    step_info['background'] = 'True'
    process_step_definition(step, step_info)
    parent_node.append(step_info)
    return step_info


def generate_execution_info(context, features, test=False):
    # Generate scenario list
    feature_list = []

    for feature in features:
        scenario_list = []
        id_feature = random.getrandbits(16)
        for feature_scenario in feature.scenarios:
            scenarios = []
            if feature_scenario.keyword == 'Scenario':
                scenarios = [feature_scenario]
            elif feature_scenario.keyword == 'Scenario Outline':
                scenarios = feature_scenario.scenarios
            scenario_list = _processing_scenarios(scenarios, scenario_list, id_feature)[
                1
            ]

        if scenario_list:
            feature_info = {}
            for attrib in ('name', 'status', 'duration'):
                value = getattr(feature, attrib)
                value = value.name if attrib == 'status' else value
                feature_info[attrib] = value
            feature_info['filename'] = text(feature.filename)
            feature_info['scenarios'] = scenario_list
            feature_info['background'] = _processing_background_feature(feature)
            feature_info['id'] = id_feature
            feature_list.append(feature_info)
    if test:
        return feature_list
    return save_info_json(context, feature_list)


def save_info_json(context, feature_list):
    environment_info = ''
    if hasattr(context, 'environment'):
        environment_info = context.environment

    output = {
        'environment': environment_info,
        'features': feature_list,
        'steps_definition': global_vars.steps_definitions,
    }
    if multiprocessing.current_process().name == 'MainProcess':
        path_info = os.path.join(
            os.path.abspath(get_env('OUTPUT')),
            global_vars.report_filenames['report_json'],
        )
    else:
        path_info = os.path.join(
            gettempdir(),
            'result{}.tmp'.format(
                multiprocessing.current_process().name.split('-')[-1]
            ),
        )
    try:
        with open(path_info, 'w') as file_info:

            def write_json():
                file_info.write(json.dumps(output))

            try_operate_descriptor(path_info, execution=write_json)
        if multiprocessing.current_process().name != 'MainProcess':
            return output
    except IOError:
        msg = (
            'The file {0} is apparently being used. Please, close it and '
            'then try again'
        )
        raise Exception(msg.format(global_vars.report_filenames['report_json']))
    except Exception as exc_json:
        msg = (
            'An error occurred trying to generate_gallery file report.json '
            'error:{0} json:{1}'
        )
        raise Exception(msg.format(exc_json, output))


# noinspection PyBroadException
def _processing_background(scenario):
    scenario_background = {'duration': 0.0, 'steps': []}
    if scenario.background:
        steps = []
        for step in scenario._background_steps:
            step_back = add_step_info_background(step, steps)
            scenario_background['duration'] += step_back['duration']
        scenario_background['name'] = str(scenario.background.name)
        scenario_background['steps'] = steps
    return scenario_background


# noinspection PyBroadException
def _processing_background_feature(feature):
    feature_background = {}
    if feature.background:
        steps = []
        for step in feature.background.steps:
            add_step_info_background(step, steps)
        feature_background['name'] = str(feature.background.name)
        feature_background['steps'] = steps
    return feature_background


def _processing_scenarios(scenarios, scenario_list, id_feature):
    scenario_outline_index = 0
    overall_status = 'passed'
    for scenario in scenarios:
        # Set MANUAL to False in order filter regardless of it
        error_msg, error_lines, error_step, error_background = _get_error_scenario(
            scenario
        )
        # pylint: disable=W0123
        if match_for_execution(scenario.tags):
            # Scenario was selectable
            scenario_info = {}
            for attrib in ('name', 'duration', 'status', 'tags'):
                value = getattr(scenario, attrib)
                value = value.name if attrib == 'status' else value
                scenario_info[attrib] = value
            scenario_info['filename'] = text(scenario.filename)
            scenario_info['feature'] = scenario.feature.name
            scenario_info['id_feature'] = id_feature
            steps = []
            for step in scenario.steps:
                add_step_info(step, steps)
            scenario_info['steps'] = steps
            scenario_info['outline_index'] = scenario_outline_index
            if scenario_info['status'] == 'failed':
                overall_status = 'failed'
            scenario_outline_index += 1
            scenario_info['background'] = _processing_background(scenario)
            scenario_info['error_msg'] = error_msg
            scenario_info['error_lines'] = error_lines
            scenario_info['error_step'] = error_step
            scenario_info['error_background'] = error_background
            scenario_info['id_hash'] = _generate_hash(scenario.name)
            if scenario.feature.name in global_vars.retried_scenarios:
                if (
                    scenario.name
                    in global_vars.retried_scenarios[scenario.feature.name]
                ):
                    scenario_info['retried'] = True

            scenario_list.append(scenario_info)
    return overall_status, scenario_list


def _get_error_scenario(scenario):
    error_lines = []
    error_msg = u''
    failing_step = None
    error_background = False
    b_steps = scenario._background_steps if scenario._background_steps else []
    for index, step in enumerate(b_steps):
        if step.status == 'undefined' or step.exception:
            failing_step = _step_to_dict(index, step)
            failing_step['background'] = 'True'
            # failing_step.keys() is forced to be a list in order to maintain compatibility
            if 'error_msg' in list(failing_step.keys()):
                error_msg = failing_step['error_msg']
            if 'error_lines' in list(failing_step.keys()):
                error_lines = failing_step['error_lines']
            if step.status == 'undefined':
                error_msg = u'step undefined'
                error_lines = []
            error_background = True
            break
    for index, step in enumerate(scenario.steps):
        if step.exception:
            failing_step = _step_to_dict(index, step)
            # failing_step.keys() is forced to be a list in order to maintain compatibility
            if 'error_msg' in list(failing_step.keys()):
                error_msg = failing_step['error_msg']
            if 'error_lines' in list(failing_step.keys()):
                error_lines = failing_step['error_lines']
            error_background = False
            break
    return error_msg, error_lines, failing_step, error_background


def _step_to_dict(index, step):
    step_info = {}
    for attrib in ('step_type', 'name', 'text', 'status'):
        step_info[attrib] = (
            text(getattr(step, attrib)) if text(getattr(step, attrib)) else ''
        )
    step_info['duration'] = 0.0
    if hasattr(step, 'duration'):
        step_info['duration'] = step.duration or 0.0
    else:
        step_info['duration'] = 0.0
    if step.exception:
        # step.exception is forced to be a str type variable
        step_info['error_msg'] = get_error_message(str(step.exception))
        step_info['error_lines'] = traceback.format_tb(step.exc_traceback)
    if step.table:
        step_info['table'] = {}
        for heading in step.table.headings:
            step_info['table'][heading] = []
            for row in step.table:
                step_info['table'][heading].append(row[heading])
    process_step_definition(step, step_info)
    step_info['index'] = index
    return step_info


def process_step_definition(step, step_info):
    definition = registry.find_step_definition(step)
    if definition:
        hash_step = _generate_hash(definition.string)
        if hash_step not in global_vars.steps_definitions:
            global_vars.steps_definitions[hash_step] = definition.string
        step_info['hash'] = hash_step
    else:
        step_info['hash'] = 0


def _generate_hash(word):
    return abs(hash(word)) % (10 ** 8)
