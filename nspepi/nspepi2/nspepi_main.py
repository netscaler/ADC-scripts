#!/usr/bin/env python2

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

"""
Convert classic expressions to advanced expressions and deprecated
commands to non-deprecated ones.

Dependency packages: PLY, pytest
"""

# Ensure that the version string conforms to PEP 440:
# https://www.python.org/dev/peps/pep-0440/
__version__ = "1.0"

import argparse
import glob
import importlib
import logging
import logging.handlers
import os
import os.path
import sys
from inspect import cleandoc
import inspect
import re

import cli_yacc
from convert_classic_expr import convert_classic_expr, \
    convert_adv_expr
import nspepi_common as common

import convert_cli_commands

# Log handlers that need to be saved from call to call
file_log_handler = None
console_log_handler = None
debug_log_handler = None

def create_file_log_handler(file_name, log_level):
    """
    Creates file logging handler.

    Args:
        file_name - log file name
        log_level - The level of logs to put in the file
    """
    # create file handler and roll logs if needed
    exists = os.path.isfile(file_name)
    file_handler = logging.handlers.RotatingFileHandler(file_name,
                                                        mode='a',
                                                        backupCount=9)
    if exists:
        file_handler.doRollover()
    # set the file log handler level
    file_handler.setLevel(log_level)
    # create formatters and add them to the handlers
    fh_format = logging.Formatter('%(asctime)s: %(levelname)s - %(message)s')
    file_handler.setFormatter(fh_format)
    return file_handler

def setup_logging(log_file_name, file_log_level, debug_file_name, console_output_needed):
    """
    Sets up logging for the program.

    Args:
        log_file_name: The name of the log file
        file_log_level: The level of logs to put in log_file_name file
        debug_file_name: The name of the debug log file
        console_output_needed: True if logs need to be seen on console
    """
    global file_log_handler
    global console_log_handler
    global debug_log_handler
    # create logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # if called multiple times, remove existing handlers
    logger.removeHandler(file_log_handler)
    logger.removeHandler(console_log_handler)
    logger.removeHandler(debug_log_handler)
    # create file handler
    file_log_handler = create_file_log_handler(log_file_name, file_log_level)
    # add the handlers to the logger
    logger.addHandler(file_log_handler)
    if debug_file_name:
        debug_log_handler = create_file_log_handler(debug_file_name, logging.DEBUG)
        logger.addHandler(debug_log_handler)
    if console_output_needed:
        # create console handler that sees even info messages
        console_log_handler = logging.StreamHandler()
        console_log_handler.setLevel(logging.INFO)
        ch_format = logging.Formatter('%(levelname)s - %(message)s')
        console_log_handler.setFormatter(ch_format)
        logger.addHandler(console_log_handler)


def classic_policy_expr(expr):
    """
    Validates that the length of expression given does not exceed 8191 chars.

    Args:
        expr: Classic policy expression whose length is to be validated

    Returns:
        expr: Classic policy expression passed-in as argument

    Raises:
        argparse.ArgumentTypeError: If length of expr exceeds 8191 chars
    """
    if (len(expr) > 8191):
        raise argparse.ArgumentTypeError("expression length exceeds 8191"
                                         " characters")
    return expr


def output_line(line, outfile, verbose):
    """
    Output a (potentially) converted line.

    Args:
        line: the line to output
        outfile: Output file to write converted commands
        verbose: True iff converted commands should also be output to console
    """
    outfile.write(line)
    if verbose:
        logging.info(line.rstrip())


def convert_config_file(infile, outfile, verbose):
    """
    Process ns config file passed in argument and convert classic policy
    expressions to advanced expressions and deprecated commands to
    non-deprecated commands.

    Args:
        infile: NS config file to be converted
        outfile: Output file to write converted commands
        verbose: True iff converted commands should also be output to console
    """
    cli_yacc.cli_yacc_init()
    # import all modules that start with convert_* so that the handler methods
    # for various commands are registered
    currentfile = os.path.abspath(inspect.getfile(inspect.currentframe()))
    currentdir = os.path.dirname(currentfile)
    for module in glob.glob(os.path.join(currentdir, 'convert_*.py')):
        importlib.import_module(os.path.splitext(os.path.basename(module))[0])
    # call methods registered to be called before the start of processing
    # config file.
    for m in common.init_methods:
        m.method(m.obj)
    lineno = 0
    for cmd in infile:
        lineno += 1
        parsed_tree = cli_yacc.cli_yacc_parse(cmd, lineno)
        if parsed_tree is not None:
            # construct dictionary key to look up registered method to call to
            # parse and transform the command to be emitted
            # Registered method can return either string or tree.
            key = " ".join(parsed_tree.get_command_type()).lower()
            if key in common.dispatchtable:
                for m in common.dispatchtable[key]:
                    for output in m.method(m.obj, parsed_tree):
                        output_line(str(output), outfile, verbose)
            else:
                output_line(str(parsed_tree), outfile, verbose)
        else:
            output_line(cmd, outfile, verbose)
    # call methods registered to be called at end of processing
    for m in common.final_methods:
        for output in m.method(m.obj):
            output_line(str(output), outfile, verbose)
    # analyze policy bindings for any unsupported bindings
    common.pols_binds.analyze()
    # Get all bind commands after reprioritizing.
    config_obj = convert_cli_commands.ConvertConfig()
    for output in config_obj.reprioritize_and_emit_binds():
        output_line(str(output), outfile, verbose)


def main():
    desc = cleandoc(
        """
        Convert classic policy expressions to advanced policy
        expressions and deprecated commands to non-deprecated
        commands.
        """)
    usage_example = cleandoc(
        """
	Usage Examples:
          i) nspepi -e "req.tcp.destport == 80"
          ii) nspepi -f ns.conf
        """)
    arg_parser = argparse.ArgumentParser(
        prog="nspepi",
        description=desc,
        epilog=usage_example,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    # create a mutually exclusive group for arguments -e and -f to specify that
    # only one of them can be accepted and not both at the same time. Also set
    # required=True to specify that at least one of them must be given as an
    # argument.
    group = arg_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-e", "--expression", action="store", type=classic_policy_expr,
        metavar="<classic policy expression>",
        help="convert classic policy expression to advanced policy"
             " expression (maximum length of 8191 allowed)")
    group.add_argument(
        "-f", "--infile", metavar="<path to ns config file>",
        help="convert Citrix ADC configuration file")
    arg_parser.add_argument(
        "-d", "--debug", action="store_true", help="log debug output")
    arg_parser.add_argument(
        "-v", "--verbose", action="store_true", help="show verbose output")
    arg_parser.add_argument(
        '-V', '--version', action='version',
        version='%(prog)s {}'.format(__version__))
    try:
        args = arg_parser.parse_args()
    except IOError as e:
        exit(str(e))
    # obtain logging parameters and setup logging
    conf_file_path = ''
    conf_file_name = 'expr'
    if args.infile is not None:
        conf_file_path = os.path.dirname(args.infile)
        conf_file_name = os.path.basename(args.infile)
    log_file_name = os.path.join(conf_file_path, 'warn_' + conf_file_name)
    debug_file_name = os.path.join(conf_file_path, 'debug_' + conf_file_name) if args.debug else None
    # For -v and -e options, logs will be seen on console and warn file.
    # For other options, logs will only be in warn file and not on console.
    setup_logging(log_file_name, logging.WARNING, debug_file_name, args.verbose or args.expression is not None)
    convert_cli_commands.convert_cli_init()
    # convert classic policy expression if given as an argument
    if args.expression is not None:
        # Check that given argument value is not a command
        if re.search(r'^\s*((add)|(set)|(bind))\s+[a-zA-Z]', args.expression, re.IGNORECASE):
            print("Error: argument e: Make sure argument value "
                  "provided is an expression and not a command")
            return
        output = convert_classic_expr(args.expression)
        # return value of convert_classic_expr will be enclosed with quotes.
        if output is not None and convert_cli_commands. \
                remove_quotes(output) == args.expression:
            # If expression is not converted, then it can be advanced
            # expression. Advanced expressions can have Q and S prefixes and
            # SYS.EVAL_CLASSIC_EXPR expression which needs to be converted.
            output = convert_adv_expr(args.expression)
        if output is not None:
            print(output)
    # convert ns config file
    elif args.infile is not None:
        new_path = os.path.join(conf_file_path, "new_" + conf_file_name)
        with open(args.infile, 'r') as infile:
            with open(new_path, 'w') as outfile:
                convert_config_file(infile, outfile, args.verbose)
                print("\nConverted config will be available in a new file new_"
                      + conf_file_name + ".\nCheck warn_" + conf_file_name +
                      " file for any warnings or errors that might have been generated.")
                if args.debug:
                    print("Check debug_" + conf_file_name + " file for debug logs.")


if __name__ == '__main__':
    main()
