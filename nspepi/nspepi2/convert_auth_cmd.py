#!/usr/bin/env python

# Copyright 2021-2023 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import copy
import logging
from collections import OrderedDict

import nspepi_common as common
from nspepi_parse_tree import *
from convert_classic_expr import *
import convert_cli_commands as cli_cmds

# TODO Some of the Client Security Expressions do not have equivalent Advanced
# expressions. This may lead to some policies being converted and some not,
# which in overall will lead to invalid config. To avoid this issue,
# disabling the Classic Authentication policy and its bindings conversion for now.

# All module names starting with "convert_" are parsed to detect and register
# class methods
@common.register_class_methods
class Authentication(cli_cmds.ConvertConfig):
    """
    Converts classic Authentication policies and
    authentication vserver bind commands of classic policies.
    """

    # override
    bind_default_goto = "NEXT"
    flow_type_direction_default = None

    def __init__(self):
        """
        Information about authentication commands.
        _converted_bind_cmd_trees - Dictionary to store converted
                                    bind commands.
            {<bind_point>: <list of parse trees related to that bind point>}
        _policy_label_priority - Needs to add priority in policy label
                                 bind commands. This variable contains
                                 last priority that is used in each
                                 policy label.
        """
        self._converted_bind_cmd_trees = OrderedDict()
        self._policy_label_priority = OrderedDict()

    @property
    def converted_bind_cmd_trees(self):
        return self._converted_bind_cmd_trees

    #@common.register_for_cmd("add", "authentication", "webAuthPolicy")
    #@common.register_for_cmd("add", "authentication", "dfaPolicy")
    def convert_webAuth_dfa_policy(self, auth_policy_parse_tree):
        """
        Converting classic webAuth/dfa policy
        to advanced authentication policy.
        Syntax:
        add authentication webAuthPolicy <name>
        -rule <classic rule> -action <action name>
        or
        add authentication dfaPolicy <name>
        -rule <classic rule> -action <action name>
        converts to
        add authentication Policy <name>
        -rule <advanced rule> -action <action name>
        """
        # Because we are currently converting authentication policies and its
        # bindings to authentication vserver only and not VPN vserver, VPN
        # global and system global bindings, we will get error for VPN
        # vserver, VPN global and system global bindings. To aviod this issue,
        # we create advanced policy which is equivalent to old classic policy,
        # give it a name, and replace all the references to the old classic
        # policy in the converted bind commands to the corresponding advanced
        # policy.
        original_tree = copy.deepcopy(auth_policy_parse_tree)
        tree_list = [original_tree]
        policy_name = auth_policy_parse_tree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        # Changing ot of the command.
        auth_policy_parse_tree.ot = "Policy"
        # Changing classic rule to advanced rule.
        cli_cmds.ConvertConfig.convert_keyword_expr(auth_policy_parse_tree,
                                                    'rule')
        if auth_policy_parse_tree.upgraded:
            self.replace_advanced_name(auth_policy_parse_tree)
            # Remove the devno so that multiple lines
            # don't have the same devno.
            if auth_policy_parse_tree.keyword_exists('devno'):
                auth_policy_parse_tree.remove_keyword('devno')
            tree_list.append(auth_policy_parse_tree)
            pol_obj.policy_type = "classic"
        else:
            pol_obj.policy_type = "advanced"
        return tree_list

    #@common.register_for_cmd("add", "authentication", "certPolicy")
    #@common.register_for_cmd("add", "authentication", "negotiatePolicy")
    #@common.register_for_cmd("add", "authentication", "tacacsPolicy")
    #@common.register_for_cmd("add", "authentication", "samlPolicy")
    #@common.register_for_cmd("add", "authentication", "radiusPolicy")
    #@common.register_for_cmd("add", "authentication", "ldapPolicy")
    #@common.register_for_cmd("add", "authentication", "localPolicy")
    def convert_other_auth_policy(self, auth_policy_parse_tree):
        """
        Converting local/ldap/radius/saml/tacacs/negotiate/cert policy to
        advanced authentication policy.
        Syntax for localPolicy:
        add authentication localPolicy <name> <classic rule>
        converts to
        add authentication Policy <name> -rule <advanced rule> -action local

        syntax for other policies:
        add authentication <policy type> <name> <classic rule> <action name>
        converts to
        add authentication Policy <name> -rule <advanced rule>
        -action <action name>
        """
        # Because we are currently converting authentication policies and its
        # bindings to authentication vserver only and not VPN vserver, VPN
        # global and system global bindings, we will get error for VPN
        # vserver, VPN global and system global bindings. To aviod this issue,
        # we create advanced policy which is equivalent to old classic policy,
        # give it a name, and replace all the references to the old classic
        # policy in the converted bind commands to the corresponding advanced
        # policy.
        original_tree = copy.deepcopy(auth_policy_parse_tree)
        tree_list = [original_tree]
        policy_name = auth_policy_parse_tree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        is_local_policy = (auth_policy_parse_tree.ot.lower() == "localpolicy")

        # Changing ot of the command.
        auth_policy_parse_tree.ot = "Policy"

        # Changing classic rule to advanced rule
        # positional to keyword.
        cli_cmds.ConvertConfig.convert_pos_expr(auth_policy_parse_tree, 1)
        if not auth_policy_parse_tree.upgraded:
            pol_obj.policy_type = "advanced"
            return tree_list
        advanced_expr = auth_policy_parse_tree.positional_value(1).value
        rule_keyword = CLIKeywordParameter(CLIKeywordName("rule"))
        rule_keyword.add_value(advanced_expr)
        auth_policy_parse_tree.add_keyword(rule_keyword)
        auth_policy_parse_tree.remove_positional(1)

        # Changing action from positional to keyword
        action = None
        if is_local_policy:
            action_name = "LOCAL"
        else:
            action_name = auth_policy_parse_tree.positional_value(1).value
            auth_policy_parse_tree.remove_positional(1)
        action_keyword = CLIKeywordParameter(CLIKeywordName("action"))
        action_keyword.add_value(action_name)
        auth_policy_parse_tree.add_keyword(action_keyword)

        auth_policy_parse_tree.set_upgraded()
        pol_obj.policy_type = "classic"
        self.replace_advanced_name(auth_policy_parse_tree)
        # Remove the devno so that multiple lines
        # don't have the same devno.
        if auth_policy_parse_tree.keyword_exists('devno'):
            auth_policy_parse_tree.remove_keyword('devno')
        tree_list.append(auth_policy_parse_tree)
        return tree_list

    def replace_advanced_name(self, auth_policy_parse_tree):
        """
        Replace policy name with the corresponding advanced policy name and
        store the policy name as classic as this is converted command.
        auth_policy_parse_tree - bind command parse tree
        """
        policy_name = auth_policy_parse_tree.positional_value(0).value
        advanced_policy_name = "nspepi_adv_" + policy_name
        auth_policy_parse_tree.positional_value(0) \
            .set_value(advanced_policy_name)
        pol_obj = common.Policy(advanced_policy_name,
                                self.__class__.__name__, "classic")
        common.pols_binds.store_policy(pol_obj)

    def convert_auth_policy_auth_vserver_bind(self, bind_cmd_parse_tree):
        """
        This is a helper function which converts bind command
        of authentication policy to authentication vserver.
        If advanced policy is bound, returns the original tree.
        If classic policy which is converted is bound
        then convert the command as below:
        classic policies can be bound as primary, secondary, groupExtraction.
        1. For primary policy, add -priority or update if already present.
           since same priority can be given multiple times in classic policies.
           Example:
               bind authentication vserver <vserver_name> -policy <policy_name>
               converts to
               bind authentication vserver <vserver_name> -policy <policy_name>
                   -priority <priority> -gotoPriorityExpression NEXT
        2. For secondary policy, follow the below steps
            1) create authentication policylabel
               <vserver_name>_secondary_auth_label
            2) Bind all policies which are bound as
               secondary to this policy label
            3) Add -nextfactor <vserver_name>_seconday_auth_label
               to all policies which are bound as primary to that bind point.
        3. For groupExtraction policy, follow the below steps
            1) create authentication policylabel
               <vserver_name>_group_auth_label
            2) Bind all policies with group_extraction
               to this policy label.
            3) Add -nextfactor <vserver_name>_group_auth_label
               to all policies which has -secondary
            Example:
               bind authentication vserver v1 -policy p1
               bind authentication vserver v1 -policy p2
               bind authentication vserver v1 -policy p3 -secondary
               bind authentication vserver v1 -policy p4 -secondary
               bind authentication vserver v1 -policy p5 -groupExtraction
               Converts to
               add authentication policylabel v1_group_auth_label
               add authentication policylabel v1_secondary_auth_label
               bind authentication vserver v1 -policy p1 -priority 10
                   -nextFactor v1_secondary_auth_label
                   -gotoPriorityExpression NEXT
               bind authentication vserver v1 -policy p2 -priority 20
                   -nextFactor v1_secondary_auth_label
                   -gotoPriorityExpression NEXT
               bind authentication policylabel v1_secondary_auth_label
                   -policyName p3 -priority 30 -nextFactor v1_group_auth_label
                   -gotoPriorityExpression NEXT
               bind authentication policylabel v1_secondary_auth_label
                   -policyName p4 -priority 40 -nextFactor v1_group_auth_label
                   -gotoPriorityExpression NEXT
               bind authentication policylabel v1_group_auth_label
                   -policyName p5 -priority 30 -gotoPriorityExpression NEXT
        """
        policy_name = bind_cmd_parse_tree.keyword_value("policy")[0].value
        policy_type = common.pols_binds.policies[policy_name].policy_type
        if policy_type == "advanced":
            return [bind_cmd_parse_tree]
        # Getting bind point name
        vserver_name = bind_cmd_parse_tree.positional_value(0).value
        bind_point = "auth_vserver_" + vserver_name
        sec_auth_policy_label = vserver_name + "_secondary_auth_label"
        group_factor_policy_label = vserver_name + "_group_auth_label"

        # Checking for -secondary and -groupExtraction.
        # When both options are not present, it means
        # policy bound is primary.
        if bind_cmd_parse_tree.keyword_exists("secondary"):
            # If entry for bind_point is not in dictionary,
            # then add one entry.
            if bind_point not in self._converted_bind_cmd_trees:
                self._converted_bind_cmd_trees[bind_point] = []
            # If secondary policy label is not added already, add it.
            if not self.is_policy_label_added(
                    bind_point, sec_auth_policy_label):
                self.add_policy_label(bind_point, sec_auth_policy_label)
                self.add_nextfactor_to_primary(
                    bind_point, sec_auth_policy_label)
            # Bind policy to secondary policy label
            self.bind_policy_label(
                bind_point, sec_auth_policy_label, policy_name)
        elif bind_cmd_parse_tree.keyword_exists("groupExtraction"):
            # If entry for bind_point is not in dictionary,
            # then add one entry
            if bind_point not in self._converted_bind_cmd_trees:
                self._converted_bind_cmd_trees[bind_point] = []
            # If group policy label is not added already, add it.
            if not self.is_policy_label_added(
                    bind_point, group_factor_policy_label):
                self.add_policy_label(bind_point, group_factor_policy_label)
                self.add_nextfactor_to_secondary(
                    bind_point, sec_auth_policy_label,
                    group_factor_policy_label)
            # Bind policy to group policy label
            self.bind_policy_label(
                bind_point, group_factor_policy_label, policy_name)
        else:
            if bind_point not in self._converted_bind_cmd_trees:
                self._converted_bind_cmd_trees[bind_point] = []
            # Replace with advanced policy name.
            advanced_policy_name = "nspepi_adv_" + policy_name
            self.update_tree_arg(bind_cmd_parse_tree, "policy",
                                 advanced_policy_name)
            self._converted_bind_cmd_trees[bind_point].append(
                                        bind_cmd_parse_tree)

        return []

    def is_policy_label_added(self, bind_point, label_name):
        """
        Checks whether policy label is added or not.
        bind_point - bind_point name which is used as key in dictionary
        label_name - policy label name that has to be checked for.
        Returns True, if add policylabel tree is added to
        _converted_bind_cmd_trees[bind_point].
        command:
                 add authentication policylabel <label_name>
        """
        cmd_list = self._converted_bind_cmd_trees[bind_point]
        for cmd_parse_tree in cmd_list:
            if (cmd_parse_tree.ot.lower() == "policylabel" and
                    cmd_parse_tree.positional_value(0).value == label_name):
                return True
        return False

    def add_policy_label(self, bind_point, label_name):
        """
        Creates parse tree for "add authentication  policylabel" command
        with name label_name.
        Command:
                add authentication policylabel <label_name>
        Saves the parse tree in _converted_bind_cmd_trees dictionary.
        bind_point - bind_point name which is used as key in dictionary
        label_name - Authentication policy label name that has to be added.
        """
        # Tree construction
        pol_label_tree = CLICommand("add", "authentication", "policylabel")
        pos = CLIPositionalParameter(label_name)
        pol_label_tree.add_positional(pos)
        # Save in dictionary
        self._converted_bind_cmd_trees[bind_point].insert(0, pol_label_tree)

    def bind_policy_label(self, bind_point, policy_label, policy_name):
        """
        Creates parse tree for "bind authentication policylabel" command with
        given policy label and policy.
        command:
          bind authentication policylabel <labelName> -policyName <string>
          -priority <positive_integer> -gotoPriorityExpression NEXT
        Saves the parse tree in _converted_bind_cmd_trees dictionary.
        bind_point   - bind_point name which is used as key in dictionary
        policy_label - Policy label name to which policy has to be bound
        policy_name  - Policy to be bound to policy label
        """
        # Tree construction
        if policy_label not in self._policy_label_priority:
            self._policy_label_priority[policy_label] = 0
        self._policy_label_priority[policy_label] += 100
        bind_label_tree = CLICommand("bind", "authentication", "policylabel")
        pos = CLIPositionalParameter(policy_label)
        bind_label_tree.add_positional(pos)
        policy_key = CLIKeywordParameter(CLIKeywordName("policyName"))
        advanced_policy_name = "nspepi_adv_" + policy_name
        policy_key.add_value(advanced_policy_name)
        bind_label_tree.add_keyword(policy_key)
        priority_key = CLIKeywordParameter(CLIKeywordName("priority"))
        priority_key.add_value(str(self._policy_label_priority[policy_label]))
        bind_label_tree.add_keyword(priority_key)
        goto_key = \
            CLIKeywordParameter(CLIKeywordName("gotoPriorityExpression"))
        goto_key.add_value("NEXT")
        bind_label_tree.add_keyword(goto_key)
        # Save in dictionary
        self._converted_bind_cmd_trees[bind_point].append(bind_label_tree)

    def add_nextfactor_to_primary(self, bind_point, label_name):
        """
        Adds -nextFactor <secondary_label_name> to all the policies which are
        bound as primary to that bindpoint
        Primary policies are bound to authentication vserver by the following
        command:
                bind authentication vserver <vserver_name> -policy <name>
        bind_point   - bind_point name which is used as key in dictioanry
        label_name   - Policy label name which should be added as nextfactor
        """
        cmd_list = self._converted_bind_cmd_trees[bind_point]
        for index in range(len(cmd_list)):
            cmd_parse_tree = cmd_list[index]
            if ((' '.join(cmd_parse_tree.get_command_type())).lower() ==
                    "bind authentication vserver"):
                self.add_nextfactor(cmd_parse_tree, label_name)

    def add_nextfactor_to_secondary(
            self, bind_point, secondary_label_name, group_label_name):
        """
        Adds -nextFactor <group_factor_label_name> to all the policies which
        are bound as secondary to that bind point.
        Secondary policies are bound to secondary_policy_label by the
        following command:
                 bind authentication policylabel <labelName>
                 -policyName <string>
                 -priority <positive_integer>
        bind_point           - bind point name which is used as
                               key in dictionary
        group_label_name     - Policy label name which should be
                               added as nextFactor
        secondary_label_name - Policy label name to which nextfactor
                               has to be added
        """
        cmd_list = self._converted_bind_cmd_trees[bind_point]
        for index in range(len(cmd_list)):
            cmd_parse_tree = cmd_list[index]
            if ((' '.join(cmd_parse_tree.get_command_type())).lower() ==
                    "bind authentication policylabel" and
                    cmd_parse_tree.positional_value(0).value ==
                    secondary_label_name):
                self.add_nextfactor(cmd_parse_tree, group_label_name)

    def add_nextfactor(self, tree, policy_label_name):
        """
        Adds -nextfactor to command.
        tree              - command parse tree to which nextfactor
                            has to be added
        policy_label_name - Policy label name which
                            should be added as nextfactor
        """
        nextfactor_key = CLIKeywordParameter(CLIKeywordName("nextFactor"))
        nextfactor_key.add_value(policy_label_name)
        tree.add_keyword(nextfactor_key)
        tree.set_upgraded()

    @common.register_for_cmd("bind", "authentication", "vserver")
    def convert_auth_vserver_bind(self, bind_parse_tree):
        """
        Handles Authentication vserver bind
        command.
        bind authentication vserver <name> [-policy <string>
        [-priority <positive_integer>] [-gotoPriorityExpression
        <expression>]]
        """
        if not bind_parse_tree.keyword_exists('policy'):
            return [bind_parse_tree]

        policy_name = bind_parse_tree.keyword_value("policy")[0].value
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"

        class_name = self.__class__.__name__
        policy_type = common.pols_binds.get_policy(policy_name).module
        # If policy is Authentication policy.
        if policy_type == class_name:
            return self.convert_auth_policy_auth_vserver_bind(
                                            bind_parse_tree)

        """
        Calls the method that is registered for the particular
        policy type that is bound to vserver. Returns converted_list.
        If the policy module is not registered for binding,
        then returns the original parse tree.
        """
        key = "Authentication"
        if key in common.bind_table:
            if policy_type in common.bind_table[key]:
                m = common.bind_table[key][policy_type]
                return m.method(m.obj, bind_parse_tree, policy_name,
                                priority_arg, goto_arg)
        return [bind_parse_tree]

    @common.register_for_final_call
    def get_converted_auth_bind_cmds(self):
        """
        Returns all command parse trees saved in _converted_bind_cmd_trees.
        This should be called only at the end of processing
        of entire ns.conf file.
        Return value - list of parse trees.
        """
        tree_list = []
        policy_type = self.__class__.__name__
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"
        for bind_point in self._converted_bind_cmd_trees:
            for tree in self._converted_bind_cmd_trees[bind_point]:
                if ((' '.join(tree.get_command_type())).lower() ==
                        "bind authentication vserver"):
                    policy_name = tree.keyword_value("policy")[0].value
                    tree_list += self.convert_entity_policy_bind(
                        tree, tree, policy_name,
                        policy_type, priority_arg, goto_arg)
                else:
                    tree_list.append(tree)
        return tree_list

    @common.register_for_cmd("add", "authentication", "vserver")
    def convert_add_auth_vserver(self, add_vserver_parse_tree):
        """
        Handles add authentication vserver
        """
        if cli_cmds.no_conversion_collect_data:
            return []
        protocol_type = add_vserver_parse_tree.positional_value(1).value
        vs_name = add_vserver_parse_tree.positional_value(0).value.lower()
        if protocol_type.upper() == "SSL":
            cli_cmds.authentication_ssl_vserver.append(vs_name)
        return [add_vserver_parse_tree]
