#!/usr/bin/env python

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import ply.yacc as yacc
import cli_lex
from nspepi_parse_tree import *
import logging

tokens = ('NON_KEY', 'KEY_ARG')


def p_command_empty(p):
    'command : empty'
    p[0] = None


def p_command(p):
    'command : command_name positional_parameters keyword_parameters'
    p[0] = p[1]
    p[0].add_positional_list(p[2])
    p[0].add_keyword_list(p[3])


def p_command_name(p):
    'command_name : op group ot'
    p[0] = CLICommand(p[1], p[2], p[3])


def p_command_name_no_ot(p):
    'command_name : op group'
    p[0] = CLICommand(p[1], p[2], "")


def p_op(p):
    'op : NON_KEY'
    logging.debug("CLI lex op: " + p[1])
    p[0] = p[1]


def p_group(p):
    'group : NON_KEY'
    logging.debug("CLI lex group: " + p[1])
    p[0] = p[1]


def p_ot(p):
    'ot : NON_KEY'
    logging.debug("CLI lex ot: " + p[1])
    p[0] = p[1]


def p_empty(p):
    'empty :'
    pass


def p_pos_params(p):
    'positional_parameters : positional_parameters NON_KEY'
    logging.debug("CLI lex pos: " + p[2])
    p[0] = p[1] + [CLIPositionalParameter(p[2])]


def p_pos_empty_param(p):
    'positional_parameters : empty'
    p[0] = []


def p_keyword_params(p):
    'keyword_parameters : keyword_parameters keyword_parameter'
    p[0] = p[1] + [p[2]]


def p_keyword_empty_param(p):
    'keyword_parameters : empty'
    p[0] = []


def p_key_param(p):
    'keyword_parameter : keyword keyword_value'
    p[0] = CLIKeywordParameter(p[1])
    p[0].add_value_list(p[2])


def p_keyword(p):
    'keyword : KEY_ARG'
    logging.debug("CLI lex key: " + p[1])
    p[0] = CLIKeywordName(p[1])


def p_key_val(p):
    'keyword_value : keyword_value NON_KEY'
    logging.debug("CLI lex key val: " + p[2])
    p[0] = p[1] + [p[2]]


def p_key_empty_val(p):
    'keyword_value : empty'
    p[0] = []


# This is for syntax errors
def p_error(p):
    if p is None:
        p = "EOL"
    logging.error("CLI syntax error at " + str(p))


_lexer = None
_parser = None


def cli_yacc_init():
    """ Initialize CLI command parser
    """
    global _lexer
    global _parser
    _lexer = cli_lex.Lexer()
    _parser = yacc.yacc(debug=False, write_tables=False)


def cli_yacc_parse(cmd, lineno):
    """ Parse a CLI command.
    cmd - the CLI command
    lineno - the line number of the command
    returns the parse tree or None if either "empty" line or syntax error
    """
    tree = _parser.parse(cmd, lexer=_lexer)
    if tree is not None:
        tree.original_line = cmd
        tree.lineno = lineno
    return tree
