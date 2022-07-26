# -*- coding: utf-8 -*-
"""
/*
* BehaveX - Agile test wrapper on top of Behave (BDD)
*/

This module provides a dictionary with the contents that are displayed in
test execution outputs.
"""

TEXTS = {
    'commons': {
        'expand': 'Expand the {} information',
        'collapse': 'Collapse the {} information',
        'error_background': 'Error in background',
        'framework_name': 'BehaveX',
        'framework_description': 'Agile test wrapper on top of Behave (BDD)',
        'help': {'title': 'Click here for more details'},
        'text': {'total_time': 'Total execution time'},
        'footer': {'name': 'BehaveX'},
    },
    'report': {
        'title': 'Test Report',
        'description': '',
        'modal': {
            'title': '',
            'body': '',
        },
        'muted': 'This scenario has been muted in build server reports (@MUTE tag)',
        'show_background': '(show background)',
        'hide_background': '(hide background)',
        'execution_tag': 'Execution Tag',
        'filter_tag': {'label': 'Tag'},
        'reset_filter': {'label': 'Reset'},
        'skip_fix_process': {'label': 'Skip scenarios under fix process'},
        'icon_duplicate': {'title': 'Copy link to this scenario'},
        'icon_repeat': {
            'title': 'This scenario was executed more than once (see @AUTORETRY tag)'
        },
        'filter_status': {'label': 'Status'},
    },
    'steps': {'title': 'Steps', 'description': '', 'modal': {'title': '', 'body': ''}},
    'metrics': {
        'title': 'Metrics',
        'description': '',
        'modal': {
            'title': '',
            'body': '<b>Test Automation Rate:</b> % of automated scenarios.<br>'
            '<b>Pass Rate:</b>: % of passed scenarios.<br>',
        },
    },
    'joined': {'title': '', 'description': '', 'modal': {'title': '', 'modal': 'the'}},
    'feature': {
        'serial_execution': '{0}\nRunning serial features (tagged as @SERIAL)'
        '.\n\n{0}'.format('*' * 60),
        'running_parallels': '{0}\nRunning parallel features.\n\n{0}'.format('*' * 60),
        'run_behave': u"Running feature '{}'.",
    },
    'scenario': {
        'serial_execution': u'{0}\nRunning serial scenarios (tagged as @SERIAL)'
        u'\n\n{0}'.format('*' * 60),
        'running_parallels': u'{0}\nRunning parallel scenarios\n\n{0}'.format('*' * 60),
        'run_behave': u"Running feature '{}' with scenario '{}'.",
        'duplicated_scenarios': '{0}\nThere are duplicate scenario names to run.\n'
        'Parallel test execution by scenario cannot be performed.\n'
        'Duplicated scenario names: \n{1}.\n\n{0}'.format('*' * 60, {}),
    },
    'folder': {'run_behave': u"Running folder: '{}' and feature '{}'."},
    'path': {'not_found': u'\nThe path "{}" was not found.\n'},
}
