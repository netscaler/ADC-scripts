#!/usr/bin/env python

# Copyright 2021-2023 Citrix Systems, Inc. All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import logging
import copy
from collections import OrderedDict

import nspepi_common as common
from nspepi_parse_tree import *
from convert_classic_expr import *
import convert_cli_commands as cli_cmds

# All module names starting with "convert_" are parsed to detect and register
# class methods


@common.register_class_methods
class LB(cli_cmds.ConvertConfig):
    """
    Handle lb vserver related commands.
    """

    def __init__(self):
        """
        Information needed for conversion.
        _search_patterns - compiled regular expression list
                           for searching CONTENT expression.
        _match_patterns  - compiled regular expression list
                           for matching CONTENT expression.
        """
        content_patterns = [
            r'REQ\.HTTP\.URL\s+CONTENTS((\s+-length\s+\d+)?(\s+-offset\s+\d+)?)?',
            r'URL\s+CONTENTS((\s+-length\s+\d+)?(\s+-offset\s+\d+)?)?',
            r'REQ\.HTTP\.URLQUERY\s+CONTENTS((\s+-length\s+\d+)?(\s+-offset\s+\d+)?)?',
            r'URLQUERY\s+CONTENTS((\s+-length\s+\d+)?(\s+-offset\s+\d+)?)?',
            r'REQ\.HTTP\.HEADER\s+\S+\s+CONTENTS((\s+-length\s+\d+)?(\s+-offset\s+\d+)?)?'
        ]
        self._search_patterns = []
        self._match_patterns = []
        for pattern in content_patterns:
            self._search_patterns.append(re.compile(pattern, re.I))
            self._match_patterns.append(re.compile(pattern + "$", re.I))

    @common.register_for_cmd("add", "lb", "vserver")
    def convert_lb_rule(self, add_lbvserver_parse_tree):
        """
        Converts classic lb rule to advanced.
        Syntax:
        add lb vserver <name> <serviceType> <IPAddress> <port>
        -persistenceType <persistenceType> -rule <classic rule>
        to
        add lb vserver <name> <serviceType> <IPAddress> <port>
        -persistenceType <persistenceType> -rule <advanced rule>

        In classic expressions only "CONTENTS" gives string as result.
        All other classic expressions gives boolean as result.
        In lb vserver, rule is used with -persistencetype rule.
        1. When the classic expression results to boolean(either
           ns_true or ns_false), no persistencesessions are created.
           If we convert the classic expression, then the
           advanced expression will result in either true or false.
           But for advanced expressions either true or false,
           persistencesessions are created for true and false.
           This will change the functionality. So to aviod this for
           expressions which results in boolean, remove -rule and
           -persistenceType.

        2. When the classic expression is simple and contains CONTENTS,
           replace with appropriate advanced expression.
           Possible expressions with CONTENTS:
            1. REQ.HTTP.URL CONTENTS
            2. URL CONTENTS
            3. REQ.HTTP.URLQUERY CONTENTS
            4. URLQUERY CONTENTS
            5. REQ.HTTP.HEADER <header name> CONTENTS
            6. RES.HTTP.HEADER <header name> CONTENTS (Not handling response
                              expression because this is not valid for lb rule)
           CONTENTS has length and offset option.
               REQ.HTTP.URL CONTENTS -length <number> -offset <number>

        3. When the classic expression is compound and contains CONTENTS,
           error is thrown to convert the expression manually, because
           &&, || operations are not supported on strings in advanced.
           Example:
           1. "req.http.header hdr1 contents && req.http.header hdr2 contents"
           2. "req.http.header hdr1 contents && req.vlanid == 3
                        || req.http.header hdr2 contents"
        """
        lb_protocol = add_lbvserver_parse_tree.positional_value(1).value
        lbv_name = add_lbvserver_parse_tree.positional_value(0).value.lower()
        cli_cmds.vserver_protocol_dict[lbv_name] = lb_protocol.upper()
        add_lbvserver_parse_tree = LB.convert_adv_expr_list(
                                       add_lbvserver_parse_tree, ["Listenpolicy", "resRule", "pushLabel"])
        if not add_lbvserver_parse_tree.keyword_exists("rule"):
            return [add_lbvserver_parse_tree]

        original_tree = copy.deepcopy(add_lbvserver_parse_tree)
        rule = add_lbvserver_parse_tree.keyword_value("rule")[0].value
        suffix_len_to_remove = len('.LENGTH.GT(0)"')
        for index in range(len(self._search_patterns)):
            found_expr_list = []
            if self.search_pattern(rule, index, found_expr_list):
                match_obj = self.match_pattern(rule, index)
                if match_obj[0]:
                    """ CONTENTS exists and is a simple expression.
                    Old nspepi tool with -e is used to convert the expression.
                    Tool converts CONTENT expressions in following way:
                    "REQ.HTTP.URL CONTENTS"
                    to
                    "HTTP.REQ.URL.LENGTH.GT(0)"
                    appends ".LENGTH.GT(0)" to get result as boolean when
                    expression is used in policies.
                    But when used in lb vserver, .LENGTH.GT(0) should not
                    be added.
                    """
                    rule = match_obj[1]
                    converted_rule = convert_classic_expr(rule)
                    # Removing ".length.get(0)"
                    converted_rule = converted_rule[:-suffix_len_to_remove] + \
                        "\""
                    add_lbvserver_parse_tree.keyword_value("rule")[0]. \
                        set_value(converted_rule, True)
                    add_lbvserver_parse_tree.set_upgraded()
                else:
                    # CONTENTS exists but not a simple expression.
                    # Throw error and don't convert.
                    logging.error(("-rule in the following command has to be "
                                  "converted manually: {}").format(
                                  str(add_lbvserver_parse_tree).strip()))
                return [add_lbvserver_parse_tree]

        # Case when there is no CONTENT in expression.
        add_lbvserver_parse_tree = LB.convert_keyword_expr(
            add_lbvserver_parse_tree, "rule")
        if add_lbvserver_parse_tree.upgraded:
            removed_keywords = []
            persistencetypes = ["rule", "urlpassive", "customserverid"]
            """
            When rule results in boolean value, persistenceType or lbMethod
            should be removed in the following cases.
            1. If persistenceType value is rule and resRule keyword exists,
            then persistenceType keyword should not be removed.
            2. If persistenceType value is rule and resRule keyword does not
            exists, then persistenceType keyword should be removed.
            2. If persistenceType value is urlpassive or customserverid,
            then persistenceType should be removed.
            3. If lbMethod is Token, then lbMethod should be removed.
            """
            if (add_lbvserver_parse_tree.keyword_exists("persistenceType") and
               add_lbvserver_parse_tree.keyword_value("persistenceType")[0].
               value.lower() in persistencetypes and not
               add_lbvserver_parse_tree.keyword_exists("resRule")):
                add_lbvserver_parse_tree.remove_keyword("persistenceType")
                removed_keywords.append("persistenceType")
            if (add_lbvserver_parse_tree.keyword_exists("lbMethod") and
               add_lbvserver_parse_tree.keyword_value("lbMethod")[0].value.
               lower() == "token"):
                add_lbvserver_parse_tree.remove_keyword("lbMethod")
                removed_keywords.append("lbMethod")
            if len(removed_keywords) > 0:
                removed_keywords.append("rule")
                add_lbvserver_parse_tree.remove_keyword("rule")
                logging.warning(("-rule classic expression results in boolean "
                                 "value. The equivalent advanced expression "
                                 "will result boolean value in string "
                                 "format. This will result in functionality "
                                 "change when rule is used for persistenceType"
                                 " or lbMethod. To aviod the functionality "
                                 "change, {} command is modified by removing "
                                 "the following keywords: {}.").format(
                                 str(original_tree).strip(),
                                 ", ".join(removed_keywords)))
        return [add_lbvserver_parse_tree]

    def search_pattern(self, rule, index, found_expr_list):
        """
        Searches for CONTENT expression in rule expression and in
        named expressions if included.
        Returns True if CONTENT expression is found.
        rule - Expression in which CONTENT expression should be searched.
        index - CONTENT expression index in _search_patterns list.
        found_expr_list - List of the classic named expressions found in the expression.
        """
        expr_list = cli_cmds.get_classic_expr_list(rule)
        if self._search_patterns[index].search(rule):
            return True
        else:
            for expr in expr_list:
                lower_expr_name = expr[0].lower()
                if (lower_expr_name not in found_expr_list):
                    found_expr_list.append(lower_expr_name)
                    if (lower_expr_name in cli_cmds.named_expr):
                        expr_rule = cli_cmds.named_expr[lower_expr_name]
                        if self.search_pattern(expr_rule, index, found_expr_list):
                            return True
            return False

    def match_pattern(self, rule, index):
        """
        Matches for CONTENT expression in rule expression and in
        named expressions if included.
        rule - Expression which should be matched with CONTENT expression.
        index - CONTENT expression index in _match_patterns list.
        Returns 2 values:
            boolean value - True if macthed with CONTENT expression.
            rule - Rule with which expression got matched.
        """
        expr_list = cli_cmds.get_classic_expr_list(rule)
        if self._match_patterns[index].match(rule):
            return [True, rule]
        else:
            if len(expr_list) == 0 or len(expr_list) > 1:
                return [False]
            else:
                # Case when one named expression exists in rule.
                expr_name = expr_list[0][0]
                # When rule is complex.
                # Example: "true && e1"
                if rule != expr_name:
                    return [False]
                expr_rule = cli_cmds.named_expr[expr_name.lower()]
                return self.match_pattern(expr_rule, index)

    @common.register_for_cmd("bind", "lb", "vserver")
    def convert_lb_vserver_bind(self, bind_parse_tree):
        """
        Handles lb vserver bind command.
        bind lb vserver <name> -policyName <string>
        """
        if not bind_parse_tree.keyword_exists('policyName'):
            return [bind_parse_tree]

        policy_name = bind_parse_tree.keyword_value("policyName")[0].value
        policy_type = common.pols_binds.get_policy(policy_name).module
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"

        """
        Calls the method that is registered for the particular
        policy type that is bound to LB. Returns converted_list.
        If the policy module is not registered for binding,
        then returns the original parse tree.
        """
        key = "LB"
        if key in common.bind_table:
            if policy_type in common.bind_table[key]:
                m = common.bind_table[key][policy_type]
                return m.method(m.obj, bind_parse_tree, policy_name,
                                priority_arg, goto_arg)
        return [bind_parse_tree]
