#!/usr/bin/env python2

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import logging
import subprocess
from nspepi_parse_tree import CLIParseTreeNode
import nspepi_common as common


def check_classic_expr(classic_expr):
    tree_obj = CLIParseTreeNode()
    info_msg = 'INFO: Expression is not converted' + \
        ' - most likely it is a valid advanced expression'
    warn_msg = 'WARNING: Line numbers which has ' + \
        'more than 8191 characters length: 0'
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
    if nspepi_tool_output.startswith('ERROR:'):
        """old nspepi tool throws "ERROR: Expression is in blocked list
        of conversion" error for vpn client security expression.
        We are not removing client security expressions, so these
        are valid expressions."""
        nspepi_tool_output = tree_obj.normalize(classic_expr, True)
    elif nspepi_tool_output.endswith(info_msg):
        """old nspepi tool didn't convert the expression,
        so return input expression"""
        nspepi_tool_output = tree_obj.normalize(classic_expr, True)
    elif nspepi_tool_output.endswith(warn_msg):
        logging.warning(nspepi_tool_output)
        """ If expression has more than 8191 characters, old nspepi
        tool gives warning message at the end of the output.

        old nspepi tool output:
        <advanced_expr> WARNING: Total number of warnings due to
        expressions length greater than 8191 characters: 1
        WARNING: Line numbers which has more than 8191 characters length: 0

        Removing warning message from the output
        """
        expr_end_pos = nspepi_tool_output.find("WARNING")
        nspepi_tool_output = nspepi_tool_output[0:expr_end_pos]
        nspepi_tool_output = nspepi_tool_output.rstrip()

    return nspepi_tool_output
