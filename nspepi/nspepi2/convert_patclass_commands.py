#!/usr/bin/env python2

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import nspepi_common as common
import convert_cli_commands as cli_cmds
from nspepi_parse_tree import *

# All module names starting with "convert_" are parsed to detect and register
# class methods

@common.register_class_methods
class PATCLASS(cli_cmds.ConvertConfig):

    @common.register_for_cmd("add", "policy", "patclass")
    def convert_add_patclass(self, tree):
        """
        Process: add policy patclass <patclass name>

        Args:
            tree: Command parse tree for add policy patclass command

        Returns:
            tree: Processed command parse tree for add policy patclass command
        """
        patset_tree = CLICommand('add', 'policy', 'patset')
        name = CLIPositionalParameter(tree.positional_value(0).value)
        patset_tree.add_positional(name)
        return [patset_tree]

    @common.register_for_cmd("bind", "policy", "patclass")
    def convert_bind_patclass(self, tree):
        """
        Process: bind policy patclass <patclass name> <pattern>

        Args:
            tree: Command parse tree for bind policy patclass command

        Returns:
            tree: Processed command parse tree for bind policy patclass command
        """
        patset_tree = CLICommand('bind', 'policy', 'patset')
        name = CLIPositionalParameter(tree.positional_value(0).value)
        pattern = CLIPositionalParameter(tree.positional_value(1).value)
        patset_tree.add_positional(name)
        patset_tree.add_positional(pattern)
        return [patset_tree]
