#!/usr/bin/env python

# Copyright 2021-2023 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import logging
from collections import OrderedDict

import nspepi_common as common
import nspepi_parse_tree
import convert_cli_commands as cli_cmds


@common.register_class_methods
class CMP(cli_cmds.ConvertConfig):
    """
    Converts classic CMP policies and
    bind command.
    CMP policies can be bound to cmp global,
    LB, CS, CR vserver.
    """

    # override
    flow_type_direction_default = "RESPONSE"
    # Classic built-in policy names and there corresponding
    # advanced built-in policy names.
    built_in_policies = {
        "ns_cmp_content_type": "ns_adv_cmp_content_type",
        "ns_cmp_msapp": "ns_adv_cmp_msapp",
        "ns_cmp_mscss": "ns_adv_cmp_mscss",
        "ns_nocmp_mozilla_47": "ns_adv_nocmp_mozilla_47",
        "ns_nocmp_xml_ie": "ns_adv_nocmp_xml_ie"
    }

    def __init__(self):
        """
        Information about CMP commands.
        _cmp_bind_info        - Contains CMP policies binding info.
                                key - bind point(possible values:
                                      ""(which indicates the compression global
                                      bind point) or <vserver name>).
                                value - dictionary with the following keys
                                        "bind_parse_trees",
                                        "is_classic_policy_bound",
                                        "is_advanced_policy_bound".
        _initial_cmp_parameter- Initial CMP parameter policy type.
        _classic_builtin_bind - Contains info about classic builtin policy
                                bindings.
                                key - bind command parse tree in which classic
                                      built-in policy name is replaced with the
                                      corresponding advanced built-in policy
                                      name.
                                value - classic built-in policy name.
        """
        self._cmp_bind_info = OrderedDict()
        self._initial_cmp_parameter = "advanced"
        self._classic_builtin_bind = OrderedDict()

    @common.register_for_init_call
    def store_builtin_cmp_policies(self):
        """
        Creates and stores Policy object for built-in CMP policies.
        """
        self.store_builtin_policies()

    @common.register_for_cmd("set", "cmp", "parameter")
    def set_cmp_parameter(self, cmp_param_tree):
        """
        Remove policyType parameter from the command
        Syntax:
           set cmp parameter -policyType ADVANCED
        """
        if cmp_param_tree.keyword_exists("policyType"):
            self._initial_cmp_parameter = \
                cmp_param_tree.keyword_value("policyType")[0].value.lower()
            cmp_param_tree.remove_keyword("policyType")
            if cmp_param_tree.get_number_of_params() == 0:
                return []
        return [cmp_param_tree]

    @common.register_for_cmd("set", "cmp", "policy")
    def set_cmp_policy(self, cmp_policy_tree):
        """
        Classic CMP built-in policies cannot be changed using set command.
        Advanced CMP built-in policies can be changed using set command and
        set command is saved in ns.conf. Since we are replacing the classic
        built-in policy name with corresponding advanced built-in policy name,
        if advanced policy is changed with set command, then functionality
        will change. So, if advanced built-in policy is changed then add new
        advanced policy which will be equivalent to classic built-in policy.
        cmp_policy_tree - set cmp policy command parse tree
        """
        advanced_builtin_policy = {
            "ns_adv_cmp_content_type": {
                                "classic": "ns_cmp_content_type",
                                "rule": "HTTP.RES.HEADER(\"Content-Type\")" +
                                        ".CONTAINS(\"text\")",
                                "resAction": "COMPRESS"
            },
            "ns_adv_cmp_msapp": {
                                "classic": "ns_cmp_msapp",
                                "rule": "ns_msie_adv && (HTTP.RES.HEADER" +
                                        "(\"Content-Type\").CONTAINS(\"appl" +
                                        "ication/msword\") || HTTP.RES.HEADE" +
                                        "R(\"Content-Type\").CONTAINS(\"" +
                                        "application/vnd.ms-excel\") || " +
                                        "HTTP.RES.HEADER(\"Content-Type\")" +
                                        ".CONTAINS(\"application/vnd.ms-" +
                                        "powerpoint\"))",
                                "resAction": "COMPRESS"
            },
            "ns_adv_cmp_mscss": {
                                "classic": "ns_cmp_mscss",
                                "rule": "ns_msie_adv && HTTP.RES.HEADER" +
                                        "(\"Content-Type\").CONTAINS" +
                                        "(\"text/css\")",
                                "resAction": "COMPRESS"
            },
            "ns_adv_nocmp_mozilla_47": {
                                "classic": "ns_nocmp_mozilla_47",
                                "rule": "HTTP.REQ.HEADER(\"User-Agent\")." +
                                        "CONTAINS(\"Mozilla/4.7\") && HTTP." +
                                        "RES.HEADER(\"Content-Type\")." +
                                        "CONTAINS(\"text/css\")",
                                "resAction": "NOCOMPRESS"
            },
            "ns_adv_nocmp_xml_ie": {
                                "classic": "ns_nocmp_xml_ie",
                                "rule": "ns_msie_adv && HTTP.RES.HEADER" +
                                        "(\"Content-Type\").CONTAINS" +
                                        "(\"text/xml\")",
                                "resAction": "NOCOMPRESS"
            }
        }
        tree_list = [cmp_policy_tree]
        adv_policy_name = cmp_policy_tree.positional_value(0).value
        if adv_policy_name in advanced_builtin_policy:
            # Tree construction
            policy_name = "nspepi_adv_" + adv_policy_name
            policy_tree = nspepi_parse_tree.CLICommand("add", "cmp", "policy")
            pos = nspepi_parse_tree.CLIPositionalParameter(policy_name)
            policy_tree.add_positional(pos)
            rule_key = nspepi_parse_tree.CLIKeywordParameter(
                nspepi_parse_tree.CLIKeywordName("rule"))
            rule_key.add_value(
                advanced_builtin_policy[adv_policy_name]["rule"])
            policy_tree.add_keyword(rule_key)
            action_key = nspepi_parse_tree.CLIKeywordParameter(
                nspepi_parse_tree.CLIKeywordName("resAction"))
            action_key.add_value(
                advanced_builtin_policy[adv_policy_name]["resAction"])
            policy_tree.add_keyword(action_key)
            tree_list.append(policy_tree)
            # Update policy name in built_in_policies dictionary.
            self.built_in_policies[advanced_builtin_policy[adv_policy_name][
                "classic"]] = policy_name
        return tree_list

    @common.register_for_cmd("add", "cmp", "policy")
    def convert_cmp_policy(self, cmp_policy_tree):
        """
        Converts classic cmp policy to advanced.
        Syntax:
        add cmp policy <name> -rule <classic_rule>
        -resAction <string>
        Converts to
        add cmp policy <name> -rule <advanced_rule>
        -resAction <string>
        """
        policy_name = cmp_policy_tree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        cli_cmds.ConvertConfig.convert_keyword_expr(cmp_policy_tree, 'rule')
        pol_obj.policy_type = ("classic"
                               if cmp_policy_tree.upgraded else "advanced")
        return [cmp_policy_tree]

    @common.register_for_cmd("bind", "cmp", "global")
    def convert_cmp_global_bind(self, bind_cmd_tree):
        """
        Handles CMP policy bindings to cmp global.
        Syntax for classic policy binding:
            bind cmp global <policyName> [-priority <positive_integer>]
            [-state (ENABLED/DISABLED)]
        When classic CMP policy is bound:
        1. If -state is DISABLED, comment the bind command.
        2. Add -type RES_DEFAULT keyword.
        3. Throw error when functionality may change.
        """
        # Comment the bind command and throw warning when
        # state is disabled.
        if bind_cmd_tree.keyword_exists("state") and \
                bind_cmd_tree.keyword_value("state")[0].value.lower() == \
                "disabled":
            logging.warning((
                "Following bind command is commented out because"
                " state is disabled. If state is disabled, then command"
                " is not in use. Since state parameter is not supported"
                " with the advanced configuration, so if we convert this"
                " config then functionality will change. If command is"
                " required please take a backup because comments will"
                " not be saved in ns.conf after triggering 'save ns config' : [{}]").
                format(str(bind_cmd_tree).strip())
            )
            return ["#" + str(bind_cmd_tree)]

        policy_name = bind_cmd_tree.positional_value(0).value
        self.replace_builtin_policy(bind_cmd_tree, policy_name, 0)
        bind_point = ""
        self.update_bind_info(bind_cmd_tree, bind_point)
        return []

    @common.register_for_bind(["LB", "ContentSwitching", "CacheRedirection"])
    def convert_cmp_policy_vserver_bind(
            self, bind_cmd_tree, policy_name, priority_arg, goto_arg):
        """
        Handles CMP policy binding to LB vserver,
        CS vserver, CR vserver.
        Syntax for classic CMP policy binding:
        bind lb/cr/cs vserver <name> -policyName <string>
        [-priority <number>]
        when classic cmp policy is bound:
        1. Add -type RESPONSE keyword.
        2. Throw error when functionality may change.
        """
        vserver_name = bind_cmd_tree.positional_value(0).value
        self.replace_builtin_policy(bind_cmd_tree, policy_name, "policyName")
        bind_point = vserver_name
        self.update_bind_info(bind_cmd_tree, bind_point)
        return []

    def replace_builtin_policy(self, bind_cmd_tree, policy_name, policy_arg):
        """
        If bound policy is classic built-in policy, then replace policy name
        with advanced built-in policy.
        """
        policy_name = policy_name.lower()
        if policy_name in self.built_in_policies:
            # Update policy name to advanced policy name.
            self.update_tree_arg(bind_cmd_tree, policy_arg,
                                 self.built_in_policies[policy_name])
            self._classic_builtin_bind[bind_cmd_tree] = policy_name

    def update_bind_info(self, bind_cmd_tree, bind_point):
        """
        Appends bind command parse tree to _cmp_bind_info
        and updates the bind_info.
        bind_cmd_tree - bind command parse tree.
        bind_point    - Policy bind point.
        """
        if bind_point not in self._cmp_bind_info:
            self._cmp_bind_info[bind_point] = OrderedDict()
            self._cmp_bind_info[bind_point]["bind_parse_trees"] = []
            self._cmp_bind_info[bind_point]["is_classic_policy_bound"] = False
            self._cmp_bind_info[bind_point]["is_advanced_policy_bound"] = False

        # -type keyword exists only for advanced policy
        # bindings.
        if bind_cmd_tree.keyword_exists("type"):
            self._cmp_bind_info[bind_point]["is_advanced_policy_bound"] = True
        else:
            self._cmp_bind_info[bind_point]["is_classic_policy_bound"] = True
        self._cmp_bind_info[bind_point]["bind_parse_trees"]. \
            append(bind_cmd_tree)

    def check_functionality(self):
        """
        Handles if there are global bindings and
        any vserver bindings.
        Both classic and advanced policies can be bound
        to CMP global. Choosing which set of policies to
        evaluate depends on two factors.
        1. CMP global parameter
        2. policy type bound to vserver
        First preference will be vserver, if vserver
        exists and has classic policies bound to it,
        then classic policy set is selected from
        global and does not depend on global CMP parameter.
        Same way if vserver has advanced policies, then
        advanced policy set is selected from global.
        If vserver does not exists, then depending on
        global CMP parameter, policy set is choosen.
        Functionality will change in the following
        cases after conversion:
        Global bindings and CMP parameter:
        1. When both classic and advanced policies
           are bound to global.
        2. When classic policies are bound and
           cmp parameter is advanced.
        3. When advanced policies are bound and
           cmp parameter is classic.
        Global and vserver bindings:
        4. When classic policies are bound to vserver and
           advanced policies are bound to global.
        5. When advanced policies are bound to vserver and
           classic policies are bound to global.
        6. When classic policies are bound to vserver and
           both classic and advanced policies are bound to
           global.
        7. When advanced policies are bound to vserver and
           both classic and advanced policies are bound to
           global.
        Returns True if there is any conflict and functionality
        will change, else returns False.
        """
        # When both classic and advanced policies are
        # bound to cmp global. This covers case 1,6,7
        # that are mentioned above.
        global_bind_point = ""
        if self._cmp_bind_info[global_bind_point][
                "is_classic_policy_bound"] and self. \
                _cmp_bind_info[global_bind_point]["is_advanced_policy_bound"]:
            logging.error(
                "Both classic and advanced policies "
                "are bound to CMP global. Now classic policies are "
                "converted to advanced. This will change the "
                "functionality. CMP policy bindings are commented out. "
                "Modify the bindings of CMP policies manually."
                )
            return True

        conflict_exists = False
        # When Global parameter and policies bound
        # at global level does not match.
        # This covers case 2 and 3
        policy_bound = ''
        if self._cmp_bind_info[global_bind_point]["is_classic_policy_bound"]:
            policy_bound = "classic"
        else:
            policy_bound = "advanced"
        if not policy_bound == self._initial_cmp_parameter:
            logging.error(
                "There is a mismatch between global "
                "parameter and policy type that are bound. "
                "Now classic policies are converted to advanced "
                "and cmp global parameter policy type is set to "
                "advanced. This will change the functionality. "
                "CMP policy bindings are commented out. Modify "
                "the global bindings of CMP policies manually."
            )
            conflict_exists = True

        # Both global and vserver bindings.
        for bind_point in self._cmp_bind_info:
            # case 4 and 5.
            if bind_point == global_bind_point:
                continue
            if self._cmp_bind_info[global_bind_point][
                    "is_classic_policy_bound"] and self. \
                    _cmp_bind_info[bind_point]["is_advanced_policy_bound"]:
                logging.error((
                    "Classic policies are bound to cmp global "
                    "and advanced policies are bound to vserver {}."
                    " Now classic policies are converted to advanced. "
                    "This will change the functionality. CMP policy bindings "
                    "are commented out. Modify the bindings of CMP policies "
                    "manually. : [{}]").format(bind_point, bind_point)
                )
                conflict_exists = True
            elif self._cmp_bind_info[global_bind_point][
                    "is_advanced_policy_bound"] and \
                    self._cmp_bind_info[bind_point]["is_classic_policy_bound"]:
                logging.error((
                    "Advanced policies are bound to "
                    "cmp global and classic policies are bound "
                    "to vserver {}. Now classic policies are "
                    "converted to advanced. This will change the "
                    "functionality. CMP policy bindings are commented out. "
                    "Modify the bindings of CMP policies "
                    "manually. : [{}]").format(bind_point, bind_point)
                )
                conflict_exists = True
        return conflict_exists

    def global_binding_exists(self):
        """
        Returns True if there is any CMP policy
        bound to cmp global.
        """
        return "" in self._cmp_bind_info

    def vserver_binding_exists(self):
        """
        Returns True if there is any CMP policy
        bound to any vserver.
        """
        # CMP policy can be bound to global/
        # CS/CR/LB vservers.
        for bind_point in self._cmp_bind_info:
            if not bind_point == "":
                return True
        return False

    def resolve_cmp_param_global_binding(self):
        """
        Comment the policy global bindings that do not
        match the cmp parameter and throw warning.
        Returns commented out bind command list.
        """
        commented_bind_cmd_list = []
        global_bind_point = ""
        if self._initial_cmp_parameter == "classic" and \
                self._cmp_bind_info[global_bind_point][
                    "is_advanced_policy_bound"]:
            # Comment the advanced policies that are bound.
            logging.warning(
                "Initial global cmp parameter is classic and in this case "
                "advanced policies's bindings are not evaluated. Now global cmp "
                "parameter policy type is set to advanced, so existing "
                "advanced policies's bindings will be evaluted and can change "
                "the functionality. So, bindings of advanced CMP policies "
                "to cmp global are commented out. If commands are required "
                "please take a backup because comments will not be saved "
                "in ns.conf after triggering 'save ns config'."
            )
            # Iterate in reverse order, since we will be removing
            # elements from list.
            for tree in \
                    reversed(self._cmp_bind_info[global_bind_point][
                    "bind_parse_trees"]):
                if tree.keyword_exists("type"):
                    bind_cmd = '#' + str(tree)
                    # Insert at 0, to preserve the order.
                    commented_bind_cmd_list.insert(0, bind_cmd)
                    self._cmp_bind_info[global_bind_point][
                        "bind_parse_trees"].remove(tree)
        elif self._initial_cmp_parameter == "advanced" and \
                self._cmp_bind_info[global_bind_point][
                "is_classic_policy_bound"]:
            # Comment the classic policies that are bound.
            logging.warning(
                "Initial global cmp parameter is advanced and in this case "
                "classic policies's bindings are not evaluated. Now all classic CMP "
                "policies are converted to advanced, so converted policies's "
                "bindings will be evaluated and can change the functionality. So "
                "bindings of classic CMP policies to cmp global are commented "
                "out. If commands are required please take a backup "
                "because comments will not be saved in ns.conf after "
                "triggering 'save ns config'."
            )
            # Iterate in reverse order, since we will be removing
            # elements from list.
            for tree in \
                    reversed(self._cmp_bind_info[global_bind_point][
                    "bind_parse_trees"]):
                if not tree.keyword_exists("type"):
                    bind_cmd = '#' + str(tree)
                    # Insert at 0, to preserve the order.
                    commented_bind_cmd_list.insert(0, bind_cmd)
                    self._cmp_bind_info[global_bind_point][
                        "bind_parse_trees"].remove(tree)
        return commented_bind_cmd_list

    def is_same_policy_type(self):
        """
        Returns True if all vservers have same
        type of policies and matches with the
        cmp parameter.
        """
        global_bind_point = ""
        if self._initial_cmp_parameter == "classic":
            key = "is_advanced_policy_bound"
        else:
            key = "is_classic_policy_bound"
        for bind_point in self._cmp_bind_info:
            # skip for global bind point.
            if bind_point == "":
                continue
            if self._cmp_bind_info[bind_point][key]:
                return False
        return True

    @common.register_for_final_call
    def get_cmp_policy_bindings(self):
        """
        Checks if the functionality will change
        after conversion. If functionality will change,
        returns all bind command parse trees(CMP
        policy bindings) saved in _cmp_bind_info.
        If functionality will not change, calls the
        Binding infra for the priority analysis.
        This should be called only at the end of
        processing of entire ns.conf file.
        Return value - list of parse trees.
        """
        tree_list = []
        conflict_exists = False

        policy_type = self.__class__.__name__
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"

        if self.global_binding_exists() and not self.vserver_binding_exists():
            # Only global bindings.
            # Comment policy bindings which do not match
            # with cmp parameter. This will resolve the
            # issue and there won't be any functionality
            # change.
            tree_list += self.resolve_cmp_param_global_binding()
        elif self.global_binding_exists() and self.vserver_binding_exists():
            # Both vserver and global bindings.
            if self.is_same_policy_type():
                # If all the vservers uses the same policy
                # type and matches with the cmp parameter,
                # comment the global bindings that do not match
                # that policy type.
                tree_list += self.resolve_cmp_param_global_binding()
            else:
                # If policy type is not same then
                # check for the funtionality change.
                conflict_exists = self.check_functionality()

        # If functionality will change, return bind commands
        # without modifying priority and goto of bind commands.
        if conflict_exists:
            for bind_point in self._cmp_bind_info:
                for tree in \
                        self._cmp_bind_info[bind_point]["bind_parse_trees"]:
                    tree_list.append('#' + str(tree))
        else:
            # If there is no policy type conflict, use Bind
            # analysis infra for setting priority and goto.
            module = self.__class__.__name__
            for bind_point in self._cmp_bind_info:
                if bind_point == "":
                    for tree in \
                           self._cmp_bind_info[bind_point]["bind_parse_trees"]:
                        if tree in self._classic_builtin_bind:
                            policy_name = self._classic_builtin_bind[tree]
                        else:
                            policy_name = tree.positional_value(0).value
                        tree_list += self.convert_global_bind(
                            tree, tree, policy_name, module,
                            priority_arg, goto_arg)
                else:
                    for tree in \
                           self._cmp_bind_info[bind_point]["bind_parse_trees"]:
                        if tree in self._classic_builtin_bind:
                            policy_name = self._classic_builtin_bind[tree]
                        else:
                            policy_name = tree.keyword_value(
                                "policyName")[0].value
                        tree_list += self.convert_entity_policy_bind(
                            tree, tree, policy_name,
                            policy_type, priority_arg, goto_arg)
        return tree_list