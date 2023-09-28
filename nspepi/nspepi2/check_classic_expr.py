#!/usr/bin/env python

# Copyright 2021-2022 Citrix Systems, Inc.  All rights reserved.
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
        # Log the command which is failing and also the error message
        logging.error(exc.output + " : [" + exc + "]")
        return None
    nspepi_tool_output = nspepi_tool_output.decode()
    if nspepi_tool_output.startswith('ERROR:'):
        """Handles the error returned by
        old nspepi tool"""
        nspepi_tool_output = "Invalid Expression"
    elif nspepi_tool_output.endswith(info_msg):
        """old nspepi tool didn't convert the expression,
        so return input expression"""
        nspepi_tool_output = tree_obj.normalize(classic_expr, True)

    return nspepi_tool_output
