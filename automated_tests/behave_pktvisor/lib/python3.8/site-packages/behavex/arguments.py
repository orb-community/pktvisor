# -*- coding: utf-8 -*-
"""

/*
* BehaveX - Agile test wrapper on top of Behave (BDD)
*/

Parse all framework arguments, the ones from BehaveX and
the ones from Behave supported by the wrapper
"""
# __future__ has been added to maintain compatibility
from __future__ import absolute_import

import argparse

BEHAVE_ARGS = [
    'no_color',
    'color',
    'define',
    'exclude',
    'include',
    'no_junit',
    'junit',
    'junit_directory',
    'steps_catalog',
    'no_skipped',
    'show_skipped',
    'lang',
    'no_snippets',
    'snippets',
    'no_multiline',
    'multiline',
    'no_capture',
    'name',
    'capture',
    'no_capture_stderr',
    'capture_stderr',
    'no_logcapture',
    'logcapture',
    'logging_level',
    'logging_format',
    'logging_datefmt',
    'logging_filter',
    'logging_clear_handlers',
    'no_summary',
    'summary',
    'outfile',
    'quiet',
    'no_source',
    'show_source',
    'stage',
    'stop',
    'tags',
    'no_timings',
    'show_timings',
    'verbose',
    'wip',
    'expand',
    'lang_list',
    'lang_help',
    'tags_help',
]

BEHAVEX_ARGS = [
    'output_folder',
    'config',
    'dry_run',
    'tags',
    'parallel_scheme',
    'parallel_processes',
]


def parse_arguments(args):
    """Process all command line arguments"""
    parser = argparse.ArgumentParser(
        description='BehaveX - test automation wrapper on top of Behave'
    )
    parser.add_argument(
        '-c',
        '--config',
        help='BehaveX configuration file to use by default.',
        required=False,
    )
    parser.add_argument(
        '-t',
        '--tags',
        action='append',
        help='Tags used to properly filter the tests to run. \
                                When multiple --tags (-t) arguments are \
                                provided it means a logical AND \
                                (e.g. -t @TAG_1 -t @TAG_2 means \
                                @TAG_1 AND @TAG_2). \
                                When multiple comma separated tags are \
                                provided as part of the same --tags (-t) \
                                argument it means a logical OR \
                                (e.g. -t @TAG_1,@TAG_2 means \
                                @TAG_1 OR @TAG_2)',
        required=False,
    )
    parser.add_argument(
        '-o',
        '--output-folder',
        default='',
        help='Output folder where the test report \
                            will be stored. Relative paths can be \
                            provided. \
                            This argument value is accessible through \
                            the "OUTPUT" environment variable',
        required=False,
    )
    parser.add_argument(
        '-d',
        '--dry-run',
        default='',
        action='store_true',
        help='Invokes formatters without executing the steps.',
        required=False,
    )

    # ------------------- Behave arguments -------------------#
    parser.add_argument(
        '--no-color',
        '--no_color',
        help='Disable the use of ANSI color escapes.',
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '--color',
        help='Use ANSI color escapes. This is the default '
        'behaviour. This switch is used to override a '
        'configuration file setting.',
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '-D',
        '--define',
        help='Define user-specific data in config.userdata '
        'dictionary. Example: -D foo=bar to store it in '
        "config.userdata['foo'].",
        action='append',
        required=False,
    )
    parser.add_argument(
        '--exclude',
        help="Don't run feature files matching regular expression PATTERN.",
        required=False,
    )
    parser.add_argument(
        '-i',
        '--include',
        help='Only run feature files matching regular expression PATTERN.',
        required=False,
    )
    parser.add_argument(
        '--name',
        help='Only execute the feature elements which match'
        ' part of the given name. If this option is given'
        ' more than once, it will match against all the '
        'given names.',
        required=False,
    )
    parser.add_argument(
        '--no-capture',
        '--no_capture',
        help="Don't capture stdout (any stdout output will be printed immediately.)",
        default=False,
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '--capture',
        help='Capture stdout (any stdout output will be '
        'printed if there is a failure.) This is the '
        'default behaviour. This switch is used to '
        'override a configuration file setting.',
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '--no-capture-stderr',
        '--no_capture_stderr',
        help="Don't capture stderr (any stderr output will be printed immediately.)",
        default=False,
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '--capture-stderr',
        '--capture_stderr',
        help='Capture stderr (any stderr output will be pri'
        'nted if there is a failure) This is the default'
        ' behaviour. This switch is used to override a '
        'configuration file setting.',
        default=False,
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '--no-logcapture',
        '--no_logcapture',
        help="Don't capture logging. Logging configuration will be left intact.",
        action='store_true',
        default=False,
        required=False,
    )
    parser.add_argument(
        '--log-capture',
        '--log_capture',
        help='Capture logging. All logging during a step will'
        ' be captured and displayed in the event of a '
        'failure. This is the default behaviour. This '
        'switch is used to override a configuration file'
        ' setting.',
        action='store_true',
        required=False,
    )
    # parser.add_argument('--summary',
    #                     help="Display the summary at the end of the run.",
    #                     action="store_true",
    #                     required=False)
    # parser.add_argument('-q',
    #                     '--quiet',
    #                     help="Alias for --no-snippets --no-source.",
    #                     action="store_true",
    #                     required=False)
    # parser.add_argument('-s',
    #                     '--no-source',
    #                     help="Don't print the file and line of the step d"
    #                          "efinition with the steps.",
    #                     action="store_true",
    #                     required=False)
    # parser.add_argument('--show-source',
    #                     help="Print the file and line of the step definition "
    #                          "with the steps. This is the default behaviour."
    #                          "This switch is used to override a configuration"
    #                          " file setting.",
    #                     action='store_true',
    #                     required=False)
    parser.add_argument(
        '-ns',
        '--no-snippets',
        '--no_snippets',
        help="Don't print snippets for unimplemented steps.",
        default=False,
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '--stop',
        help='Stop running tests at the first failure. This argument is not '
        'supported on parallel test executions.',
        action='store_true',
        required=False,
    )
    parser.add_argument(
        '--tags-help',
        '--tags_help',
        help='Show help for tag expressions.',
        action='store_true',
        required=False,
    )
    # -------------------- adding lastly ---------------------------------------
    parser.add_argument(
        '--logging-level',
        '--logging_level',
        default='INFO',
        choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET'],
        help='Specify a level to capture logging at. The '
        'default is INFO - capturing everything.',
        required=False,
    )
    parser.add_argument(
        '--parallel-processes',
        default=1,
        type=int,
        help='quantity of threads that will enable to execute',
        required=False,
    )
    parser.add_argument(
        '--parallel-scheme',
        choices=['feature', 'scenario'],
        default='scenario',
        required=False,
    )
    parser.add_argument(
        '-ip',
        '--include-paths',
        default=[],
        nargs='*',
        help='Filter test set to the specified list of features '
        'or feature file locations (FEATURE_FILE:LINE).',
    )
    parser.add_argument(
        '-rf',
        '--run-failures',
        default='',
        action='store_true',
        help='Run behavex with the parameter --include-paths with'
        ' the value of the content from the failures.txt file'
        ' located in result output.',
        required=False,
    )
    # parser.add_argument('--logging-format',
    #                    help="Specify custom format to print statements. Uses "
    #                          " the same format as used by standard logging "
    #                        "handlers. The default is (%levelname)s:w%(name)s:"
    #                          "%(message)s%.",
    #                     required=False)
    # parser.add_argument('--logging-datefmt',
    #                     help="Specify custom date/time format to print "
    #                          "statements. Uses the same format as used by "
    #                          "standard logging handlers.",
    #                     required=False)
    #
    return parser.parse_args(args)
