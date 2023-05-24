#!/usr/bin/env python

# Copyright 2021-2023 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

from nspepi_parse_tree import *
import convert_cli_commands as cli_cmds
from collections import OrderedDict

@common.register_class_methods
class Responder(cli_cmds.ConvertConfig):
    """
    Handles responder feature to store few information for
        filter bind conversion
    resp_global_goto_exists - Set this true if existing responder policy is
             globally bound with GOTO END/USE_INVOCATION_RESULT
    resp_vserver_goto_exists - Set this true if existing responder policy is
             bound to vserver with GOTO END/USE_INVOCATION_RESULT
    """
    resp_global_goto_exists = False
    resp_vserver_goto_exists = False

    def __init__(self):
        self._noop_action_list = []
        self._terminating_action_list = ["drop", "reset"]
        self._terminating_policy_list = []

    @common.register_for_cmd("add", "responder", "action")
    def convert_responder_action(self, tree):
        """
        add responder action <name> <type> <target>
        """
        action_name = tree.positional_value(0).value.lower()
        action_type = tree.positional_value(1).value.lower()
        # If action is noop, then don't return action 
        if (action_type == "noop"):
            self._noop_action_list.append(action_name)
            return []
        tree = Responder.convert_adv_expr_list(
                tree, [2, "reasonPhrase", "headers"])

        if (action_type in [
             "respondwith", "redirect", "respondwithhtmlpage"]):
            self._terminating_action_list.append(action_name)

        return [tree]

    @common.register_for_cmd("add", "responder", "policy")
    def convert_responder_policy(self, tree):
        """
        Saved policy name in policy_list.
        add responder policy <name> <rule> <action>
        """
        policy_name = tree.positional_value(0).value
        policy_action = tree.positional_value(2).value.lower()
        if (policy_action in self._noop_action_list):
            tree.positional_value(2).set_value("NOOP")
            tree.set_upgraded()
        elif (policy_action in self._terminating_action_list):
            self._terminating_policy_list.append(policy_name.lower())

        pol_obj = common.Policy(policy_name, self.__class__.__name__,
                                "advanced")
        common.pols_binds.store_policy(pol_obj)
        tree = Responder.convert_adv_expr_list(tree, [1])
        return [tree]

    @common.register_for_cmd("bind", "responder", "global")
    def convert_responder_global(self, tree):
        """
        Handles responder global bind command.
        bind responder global <policyName> <priority>
            [<gotoPriorityExpression>] [-type <type>]
        When responder policy is bound:
        1. Check if GOTO is END/USE_INVOCATION_RESULT for
              HTTP/SSL vservers
        tree - bind command parse tree
        """
        # If no filter policy is configured, then no need to process
        # responder bindings
        if not cli_cmds.filter_policy_exists:
            return [tree]

        get_goto_arg = tree.positional_value(2).value
        policy_name = tree.positional_value(0).value
        get_bind_type = tree.keyword_value("type")[0].value
        module = self.__class__.__name__
        priority_arg = 1
        goto_arg = 2
        position = "inplace"
        bind_type_to_check = ["REQ_OVERRIDE", "REQ_DEFAULT"]
        if get_bind_type in bind_type_to_check:
            if (policy_name.lower() not in self._terminating_policy_list):
                 # Set below flags only if added vserver is of HTTP/SSL protocol
                 if get_goto_arg.upper() in ("END", "USE_INVOCATION_RESULT"):
                     Responder.resp_global_goto_exists = True
            self.convert_global_bind(
                tree, tree, policy_name, module, priority_arg, goto_arg, position)
            return []
        return [tree]

    @common.register_for_bind(["LB", "ContentSwitching", "CacheRedirection"])
    def convert_responder_vserver_bindings(
            self, bind_parse_tree, policy_name, priority_arg, goto_arg):
        """
        Handles responder policy bindings to vservers - LB, CS, CR
        Syntax for responder policy binding:
        bind lb/cr/cs vserver <name> -policyName <string>
            -priority <int> -gotoPriorityExpression <string>
            -type REQUEST
        When responder policy is bound:
        1. Check if GOTO is END/USE_INVOCATION_RESULT for HTTP/SSL vservers
        """
        # If no filter policy is configured, then no need to process
        # responder bindings
        if not cli_cmds.filter_policy_exists:
            return [bind_parse_tree]

        get_goto_arg = bind_parse_tree.keyword_value(
            "gotoPriorityExpression")[0].value
        policy_name = bind_parse_tree.keyword_value("policyName")[0].value
        vs_name = bind_parse_tree.positional_value(0).value.lower()
        module = self.__class__.__name__
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"
        if cli_cmds.vserver_protocol_dict[vs_name] in ("HTTP", "SSL"):
            # Set below flags only if vserver is of ptotocol HTTP/SSL
            if ((policy_name.lower() not in self._terminating_policy_list) and
                (get_goto_arg.upper() in ("END", "USE_INVOCATION_RESULT"))):
                 Responder.resp_vserver_goto_exists = True

            if not bind_parse_tree.keyword_exists('type'):
                keyword_arg = CLIKeywordParameter(CLIKeywordName('type'))
                keyword_arg.add_value('REQUEST')
                bind_parse_tree.add_keyword(keyword_arg)
                bind_parse_tree.set_upgraded()

            self.convert_entity_policy_bind(
                bind_parse_tree, bind_parse_tree, policy_name,
                module, priority_arg, goto_arg)
            return []
        return [bind_parse_tree]

