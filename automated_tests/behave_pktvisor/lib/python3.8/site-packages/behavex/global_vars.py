# -*- coding: utf-8 -*-
import os


class GlobalVars:
    def __init__(self):
        self._execution_path = os.environ.get('BEHAVEX_PATH')
        self._report_filenames = {
            'report_json': 'report.json',
            'report_overall': 'overall_status.json',
            'report_failures': 'failing_scenarios.txt',
        }
        self._behave_tags_file = os.path.join('behave', 'behave.tags')
        self._jinja_templates_path = os.path.join(
            self._execution_path, 'outputs', 'jinja'
        )
        self._jinja_templates = {
            'main': 'main.jinja2',
            'steps': 'steps.jinja2',
            'xml': 'xml.jinja2',
            'xml_json': 'xml_json.jinja2',
            'manifest': 'manifest.jinja2',
        }
        self._retried_scenarios = {}
        self._steps_definitions = {}

    @property
    def execution_path(self):
        return self._execution_path

    @property
    def report_filenames(self):
        return self._report_filenames

    @property
    def behave_tags_file(self):
        return self._behave_tags_file

    @property
    def jinja_templates_path(self):
        return self._jinja_templates_path

    @property
    def jinja_templates(self):
        return self._jinja_templates

    @property
    def retried_scenarios(self):
        return self._retried_scenarios

    @retried_scenarios.setter
    def retried_scenarios(self, feature_name):
        self._retried_scenarios[feature_name] = []

    @property
    def steps_definitions(self):
        return self._steps_definitions


global_vars = GlobalVars()
