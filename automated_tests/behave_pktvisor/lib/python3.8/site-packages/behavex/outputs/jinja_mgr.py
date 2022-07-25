# -*- coding: utf-8 -*-
"""
/*
* BehaveX - Agile test wrapper on top of Behave (BDD)
*/

Jinja template handler.
"""
# __future__ has been added to maintain compatibility
from __future__ import absolute_import

import os
import re
import sys
import traceback
from xml.sax.saxutils import quoteattr  # nosec

import jinja2

from behavex.conf_mgr import get_env
from behavex.execution_singleton import ExecutionSingleton
from behavex.outputs.output_strings import TEXTS
from behavex.outputs.report_utils import (
    calculate_status,
    count_by_status,
    gather_errors,
    get_error_message,
    match_for_execution,
    normalize_filename,
    pretty_print_time,
    resolving_type,
)


class TemplateHandler(metaclass=ExecutionSingleton):
    """Handler to manage all jinja templates"""

    def __init__(self, template_path):
        self.template_loader = jinja2.FileSystemLoader(searchpath=template_path)
        self.template_env = jinja2.Environment(
            loader=self.template_loader, autoescape=True
        )
        self.dictionary_texts = TEXTS
        self.add_filter(_path_exist_in_output, 'path_exist_in_output')
        self.add_filter(gather_errors, 'gather_errors')
        self.add_filter(normalize_filename, 'normalize')
        self.add_filter(_resolving_color_class, 'resolving_color_class')
        self.add_filter(pretty_print_time, 'pretty_print_time')
        self.add_filter(_get_list_exception_steps, 'get_list_exception_steps')
        self.add_filter(_print_error, 'print_error')
        self.add_filter(_print_step, 'print_step')
        self.add_filter(_print_step_json, 'print_step_json')
        self.add_filter(get_error_message, 'get_error_message')
        self.add_filter(get_lines_exception, 'get_lines_exception')
        self.add_filter(_quoteattr, 'quoteattr')
        self.add_filter(_print_tag_xml, 'print_tag_xml')
        self.add_filter(resolving_type, 'resolving_type')
        self.add_filter(self._get_text, 'get_text')
        self.add_filter(_create_progress_html, 'create_progress_html')
        self.add_filter(_export_environments_title, 'export_environments_title')
        self.add_filter(match_for_execution, 'match_for_execution')
        self.add_filter(create_tags_set, 'create_tags_set')
        self.add_filter(to_string_list, 'to_string_list')
        self.add_filter(_calculate_color, 'calculate_color')
        self.add_filter(calculate_status, 'calculate_status')
        self.add_filter(count_by_status, 'count_by_status')
        self.add_filter(_exist_extra_logs, 'exist_extra_logs')
        self.add_filter(get_extra_logs_file, 'get_extra_logs_file')
        self.add_filter(get_path_extra_logs, 'get_path_extra_logs')
        self.add_filter(get_relative_extra_logs_path, 'get_relative_extra_logs_path')
        self.add_filter(clean_invalid_xml_chars, 'CIXC')
        self.add_filter(replace_enter, 'replace_enter')
        self.add_filter(normalize_path, 'normalize_path')
        self.template_env.globals.update(get_env=get_env)
        # self.template_env.globals.keys() has been forced to be a list
        if 'get_path_log' not in list(self.template_env.globals.keys()):
            self.template_env.globals.update(get_path_log=_get_path_log)
            self.template_env.globals.update(path_join=os.path.join)

    def get_filters(self):
        return self.template_env.filters

    def get_template(self, name):
        return self.template_env.get_template(name)

    def render_template(self, template_name, parameter_template=None):
        if parameter_template is None:
            parameter_template = {}
        # This function has been forced to return a string type
        return str(self.get_template(str(template_name)).render(parameter_template))

    def add_filter(self, function_filter, name_function=None):
        if name_function is None:
            # func_name has been replaced by __name__
            self.get_filters()[function_filter.__name__] = function_filter
        elif isinstance(name_function, str):
            self.template_env.filters[name_function] = function_filter
        else:
            raise Exception('name_function must be of type str')

    def _get_text(self, key_chain):
        result = None
        keys = key_chain.split('.')
        dictionary = self.dictionary_texts
        for i, key in enumerate(keys):
            msg = 'the key "{}" not found'.format('.'.join(keys[0 : i + 1]))
            result = dictionary.get(key, msg)
            if isinstance(result, str):
                return result
            if isinstance(result, dict):
                dictionary = result
            else:
                return 'key "{}" no found '.format(msg)
        if isinstance(result, dict):
            return 'key: "{}" is incomplete'.format(key_chain)


def _exist_extra_logs(scenario):
    extra_logs_folder = get_path_extra_logs(scenario)
    if os.path.exists(extra_logs_folder):
        return len(os.listdir(extra_logs_folder)) >= 1
    return False


def get_path_extra_logs(scenario):
    extra_logs_folder = os.path.join(
        get_env('logs'),
        str(normalize_filename(scenario.get('name'))),
        'evidence',
    )
    return extra_logs_folder


def get_relative_extra_logs_path(scenario):
    return (
        os.path.sep.join(
            [
                'outputs',
                'logs',
                normalize_filename(scenario.get('name')),
                'evidence',
            ]
        )
        + os.path.sep
    )


def get_extra_logs_file(scenario):
    path_logs = get_path_extra_logs(scenario)
    return [log for log in os.listdir(path_logs)]


def _calculate_color(list_status):
    color = {'passed': 'green', 'skipped': 'grey', 'failed': 'red'}
    return color[calculate_status(list_status)]


def _print_step(step):
    return u'{0} {1} ... {2} in {3:.4}s '.format(
        step.step_type, step.name, step.status, float(step.duration)
    )


def _print_step_json(step):
    return u'{0} {1} ... {2} in {3:.4}s '.format(
        step['step_type'], step['name'], step['status'], float(step['duration'])
    )


def get_lines_exception(step):
    if step.exception:
        return u'\n'.join(
            [16 * u' ' + line for line in traceback.format_tb(step.exc_traceback)]
        ).strip()
    else:
        return u''


def _path_exist_in_output(path):
    return os.path.exists(os.path.join(os.path.abspath(get_env('OUTPUT')), path))


def _get_list_exception_steps(steps, backs_steps):
    def is_failing(step):
        return step.exception or step.status == 'undefined'

    backs_steps = [step for step in backs_steps or [] if is_failing(step)]
    return [step for step in steps if is_failing(step)] + backs_steps


def _get_path_log(scenario):
    path_logs = get_env('logs')
    # scenario.keys()  has been forced to be a list to maintain compatibility
    if 'log' in list(scenario.keys()):
        return os.path.join(path_logs, scenario['log'])
    else:
        return path_logs


def _quoteattr(string):
    return "''" if not string else quoteattr(string)


def _print_tag_xml(tags):
    if not tags:
        return ''
    return '   '.join(['@{0}'.format(tag) for tag in tags])


def _create_progress_html(total, passed=0, failed=0, skipped=0):
    div = (
        '<div class="progress-bar progress-bar-default progress-behavex-{}"'
        ' role="progressbar" style="width:{}" title="{}"></div>'
    )

    title = 'Passed: {}, Failed: {}, Not&nbsp;Run: {} '.format(passed, failed, skipped)

    skipped = float(skipped)
    passed = float(passed)
    failed = float(failed)
    total = float(total)
    if skipped == failed == 0 and passed > 0:
        return div.format('passed', '100%', title)
    elif skipped == passed == failed == total == 0:
        return div.format('skipped', '0%', '0 scenario', '')
    elif passed == failed == 0 and skipped > 0:
        return div.format('skipped', '100%;', title)
    elif passed == skipped == 0 and failed > 0:
        return div.format('failed', '100%', title)
    elif passed > 0 and failed > 0 and skipped == 0:
        result = div.format('passed', '{}%'.format(100 * passed / total), title)
        result += div.format('failed', '{}%'.format(100 * failed / total), title)
    elif passed > 0 and skipped > 0 and failed == 0:
        result = div.format('passed', '{}%'.format(100 * passed / total), title)
        result += div.format('skipped', '{}%'.format(100 * skipped / total), title)
    elif passed == 0 and skipped > 0 and failed > 0:
        result = div.format('failed', '{}%'.format(100 * failed / total), title)
        result += div.format('skipped', '{}%'.format(100 * skipped / total), title)
    else:
        result = div.format('passed', '{}%'.format(100 * passed / total), title)
        result += div.format('failed', '{}%'.format(100 * failed / total), title)
        result += div.format('skipped', '{}%'.format(100 * skipped / total), title)
    return result


def _resolving_color_class(status):
    status_lower = status.lower()
    if status_lower in ('failed', 'error'):
        return 'danger'
    elif status_lower == 'passed':
        return 'success'
    elif status_lower in ('skipped', 'untested'):
        return 'warning'
    else:
        return 'active'


# environment.keys() has been forced to be a list
def _export_environments_title(environments):
    result = ''
    max_name = max(len(list(environment.keys())[0]) for environment in environments)
    row = '{} --{}>  {}\n'
    for environment in environments:
        result += row.format(
            list(environment.keys())[0],
            '-' * (max_name - len(list(environment.keys())[0])),
            list(environment.values())[0],
        )
    return result


def create_tags_set(feature):
    result = {str(tag) for scenario in feature['scenarios'] for tag in scenario['tags']}
    return list(result)


# to_string_list has been forced to return a list
def to_string_list(tags):
    if tags is None:
        return []
    return list(map(str, tags))


def _print_error(line):
    return line


def clean_invalid_xml_chars(xml_content):
    if isinstance(xml_content, bytes):
        xml_content = xml_content.decode()
    return ''.join([clean_char(c) for c in xml_content])


def invalid_xml_remove(c):
    # stackoverflow: questions/1707890/fast-way-to-filter-illegal-xml-unicode-chars-in-python
    illegal_unichrs = [
        (0x00, 0x08),
        (0x0B, 0x0C),
        (0x0E, 0x1F),
        (0x7F, 0x84),
        (0x86, 0x9F),
        (0xFDD0, 0xFDDF),
        (0xFFFE, 0xFFFF),
    ]
    if sys.maxunicode >= 0x10000:  # not narrow build
        illegal_unichrs.extend(
            [
                (0x1FFFE, 0x1FFFF),
                (0x2FFFE, 0x2FFFF),
                (0x3FFFE, 0x3FFFF),
                (0x4FFFE, 0x4FFFF),
                (0x5FFFE, 0x5FFFF),
                (0x6FFFE, 0x6FFFF),
                (0x7FFFE, 0x7FFFF),
                (0x8FFFE, 0x8FFFF),
                (0x9FFFE, 0x9FFFF),
                (0xAFFFE, 0xAFFFF),
                (0xBFFFE, 0xBFFFF),
                (0xCFFFE, 0xCFFFF),
                (0xDFFFE, 0xDFFFF),
                (0xEFFFE, 0xEFFFF),
                (0xFFFFE, 0xFFFFF),
                (0x10FFFE, 0x10FFFF),
            ]
        )

    illegal_ranges = [
        '%s-%s' % (chr(low), chr(high))
        for (low, high) in illegal_unichrs
        if low < sys.maxunicode
    ]

    illegal_xml_re = re.compile(u'[%s]' % u''.join(illegal_ranges))
    if illegal_xml_re.search(c) is not None:
        # Replace with space
        return ' '
    else:
        return c


def clean_char(char):
    # Get rid of the ctrl characters first.
    # http://stackoverflow.com/questions/1833873/python-regex-escape-characters
    # Variable char has been forced to be a string
    char = str(char)
    char = re.sub('\x1b[^m]*m', '', char)
    # Clean up invalid xml
    char = invalid_xml_remove(char)
    replacements = [
        (u'\u201c', '"'),
        (u'\u201d', '"'),
        (u'\u001B', ' '),  # http://www.fileformat.info/info/unicode/char/1b/index.htm
        (u'\u0019', ' '),  # http://www.fileformat.info/info/unicode/char/19/index.htm
        (u'\u0016', ' '),  # http://www.fileformat.info/info/unicode/char/16/index.htm
        (u'\u001C', ' '),  # http://www.fileformat.info/info/unicode/char/1c/index.htm
        (u'\u0003', ' '),  # http://www.utf8-chartable.de/unicode-utf8-table.pl?utf8=0x
        (u'\u000C', ' '),
    ]
    for rep, new_char in replacements:
        if char == rep:
            # print ord(char), char.encode('ascii', 'ignore')
            return new_char
    return char


def replace_enter(text):
    return text.replace(os.linesep, '<br>')


def normalize_path(text):
    return os.path.normpath(text)
