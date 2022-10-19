#!/usr/bin/env python

# Copyright 2021-2022 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import logging
import subprocess
import re
import convert_cli_commands as cli_commands
import nspepi_common as common


from pi_lex import PILex
from nspepi_parse_tree import CLIParseTreeNode

eval_classic_expr = re.compile(r'SYS\s*\.\s*EVAL_CLASSIC_EXPR\s*\(\s*"',
                               re.IGNORECASE)

q_s_expr = re.compile(r'\b((Q\.HOSTNAME)|(Q\.TRACKING)|'
                    r'(Q\.METHOD)|(Q\.URL)|(Q\.VERSION)|'
                    r'(Q\.CONTENT_LENGTH)|(Q\.HEADER)|'
                    r'(Q\.IS_VALID)|(Q\.DATE)|'
                    r'(Q\.COOKIE)|(Q\.BODY)|(Q\.TXID)|'
                    r'(Q\.CACHE_CONTROL)|(Q\.USER)|'
                    r'(Q\.IS_NTLM_OR_NEGOTIATE)|'
                    r'(Q\.FULL_HEADER)|'
                    r'(Q\.LB_VSERVER)|(Q\.CS_VSERVER)|'
                    r'(S\.VERSION)|(S\.STATUS)|'
                    r'(S\.STATUS_MSG)|(S\.IS_REDIRECT)|'
                    r'(S\.IS_INFORMATIONAL)|(S\.IS_SUCCESSFUL)|'
                    r'(S\.IS_CLIENT_ERROR)|(S\.IS_SERVER_ERROR)|'
                    r'(S\.TRACKING)|(S\.HEADER)|(S\.FULL_HEADER)|'
                    r'(S\.IS_VALID)|(S\.DATE)|(S\.BODY)|'
                    r'(S\.SET_COOKIE)|(S\.SET_COOKIE2)|'
                    r'(S\.CONTENT_LENGTH)|'
                    r'(S\.CACHE_CONTROL)|(S\.TXID)|(S\.MEDIA))\b',
                    re.IGNORECASE)

def convert_classic_expr(classic_expr):
    tree_obj = CLIParseTreeNode()
    info_msg = 'INFO: Expression is not converted' + \
        ' - most likely it is a valid advanced expression'
    try:
        nspepi_tool_path = common.get_nspepi_tool_path()
        """Error message will be in the staring of
        output, whereas warning and info messages
        will be present in the last."""
        nspepi_tool_output = subprocess.check_output(
            ['perl', nspepi_tool_path, '-e', classic_expr],
            shell=False, stderr=subprocess.STDOUT)
        """ old nspepi tool adds newline character at the end
        of the converted string, so remove that character."""
        nspepi_tool_output = nspepi_tool_output.rstrip()
    except subprocess.CalledProcessError as exc:
        # Log the command which is failing
        logging.error(exc)
        # Log the error message
        logging.error(exc.output)
        return None
    nspepi_tool_output = nspepi_tool_output.decode()
    if nspepi_tool_output.startswith('ERROR:'):
        """Handles the error returned by old
        nspepi tool"""
        logging.error(nspepi_tool_output)
        return None
    elif nspepi_tool_output.endswith(info_msg):
        """old nspepi tool didn't convert the expression,
        so return input expression"""
        nspepi_tool_output = classic_expr
        # classic_expr is not enclosed in quotes.
        nspepi_tool_output = tree_obj.normalize(nspepi_tool_output, True)

    # When NSPEPI tool is used with -e option, this handles classic built-in
    # Named expressions. When tool is used with -f option, all named
    # expressions are handled here.
    nspepi_tool_output = cli_commands.ConvertConfig.replace_named_expr(
        cli_commands.remove_quotes(nspepi_tool_output))
    if nspepi_tool_output is None:
        csec_expr_info = cli_commands.has_client_security_expressions(classic_expr)
        if csec_expr_info[0]:
            cli_commands.print_csec_error_message(csec_expr_info[1])
        return None
    nspepi_tool_output = tree_obj.normalize(nspepi_tool_output, True)
    return nspepi_tool_output

def convert_adv_expr(advanced_expr):
    """
    Converts Q and S prefixes.
    Converts SYS.EVAL_CLASSIC_EXPR expression in advanced expressions to remove
    classic expressions.
    advanced_expr - Expression in which Q and S prefixes and SYS.EVAL_CLASSIC_EXPR
    expression should be replaced.
    Returns None in case of any Error. Otherwise returns converted expression.
    """
    advanced_expr = convert_q_s_expr(advanced_expr)
    return convert_sys_eval_classic_expr(advanced_expr)

def convert_q_s_expr(advanced_expr):
   """
   Convertes Q and S prefixes to use HTTP.REQ and HTTP.RES
   advanced_expr - Expression in which Q and S prefixes
   should be replaced.
   Returns converted expression.
   """
   q_s_expr_list = []
   # Get all indexes of Q and S expressions.
   for match in re.finditer(q_s_expr, advanced_expr):
       q_s_expr_list.append(match.start())
   for expr_index in reversed(q_s_expr_list):
       if (advanced_expr[expr_index] == 'Q' or
           advanced_expr[expr_index] == 'q'):
           converted_expr = "HTTP.REQ"
       else:
           converted_expr = "HTTP.RES"
       advanced_expr = (advanced_expr[0: expr_index] +
                        converted_expr +
                        advanced_expr[expr_index + 1:])
   return advanced_expr

def convert_sys_eval_classic_expr(advanced_expr):
    """
    Converts SYS.EVAL_CLASSIC_EXPR expression in advanced expressions to remove
    classic expressions.
    advanced_expr - Expression in which SYS.EVAL_CLASSIC_EXPR expression
    should be replaced.
    Returns None in case of any Error. Otherwise returns converted expression.
    """
    original_expr = advanced_expr
    advanced_expr_length = len(advanced_expr)
    sys_eval_list = []
    # Get all indexes where SYS.EVAL_CLASSIC_EXPR starts.
    for match in re.finditer(eval_classic_expr, advanced_expr):
        start_index = match.start()
        length = match.end() - match.start()
        sys_eval_list.append([start_index, length])
    for sys_exp_info in reversed(sys_eval_list):
        # arg_start_index points to opening quote in
        # SYS.EVAL_CLASSIC_EXPR("<>")
        sys_start_index = sys_exp_info[0]
        sys_length = sys_exp_info[1]
        arg_start_index = sys_start_index + sys_length - 1
        classic_exp_info = PILex.get_pi_string(
            advanced_expr[arg_start_index:])
        if classic_exp_info is None:
            logging.error("Error in converting expression: {}".format(
                original_expr))
            return None
        classic_expr = classic_exp_info[0]
        length = classic_exp_info[1]
        # arg_end_index points to closing quote in SYS.EVAL_CLASSIC_EXPR("<>").
        arg_end_index = arg_start_index + length - 1
        # Handle spaces between closing quote and closing brace.
        sys_end_index = arg_end_index + 1
        while(sys_end_index < advanced_expr_length and
              advanced_expr[sys_end_index] != ')' and
              advanced_expr[sys_end_index] in " \t\r"):
            sys_end_index += 1
        if (sys_end_index >= advanced_expr_length or
           advanced_expr[sys_end_index] != ')'):
            logging.error("Error in converting expression: {}".format(
                original_expr))
            return None
        converted_expr = convert_classic_expr(classic_expr)
        if converted_expr is not None:
            # Result from convert_classic_expr will have enclosing quotes.
            converted_expr = cli_commands.remove_quotes(converted_expr)
        if converted_expr is None or converted_expr == classic_expr:
            logging.error("Error in converting expression: {}".format(
                original_expr))
            return None
        # Converted expression should be enclosed in braces because
        # SYS.EVAL_CLASSIC_EXPR can have && or ||.
        advanced_expr = (advanced_expr[0: sys_start_index] + '(' +
                         converted_expr + ')' +
                         advanced_expr[sys_end_index + 1:])
    tree_obj = CLIParseTreeNode()
    advanced_expr = tree_obj.normalize(advanced_expr, True)
    return advanced_expr
