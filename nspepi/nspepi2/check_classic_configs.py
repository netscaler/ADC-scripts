#!/usr/bin/env python2

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import copy

import cli_lex
import nspepi_common as common
import check_classic_expr
from nspepi_parse_tree import *


def check_configs_init():
    """Initialize global variables uses by this module"""
    global policy_entities_names
    global classic_entities_names
    global named_expr
    named_expr = {}
    policy_entities_names = set()
    classic_entities_names = set()
    # Register built-in named expressions.
    NamedExpression.register_built_in_named_exprs()


def remove_quotes(val):
    """
        Helper function to remove the surrounding
        quotes from a CLI parameter.
        val - CLI parameter that needs quotes removed.
        Returns the dequoted CLI parameter
    """
    result = val
    if val.startswith('"') or val.startswith("'"):
        lexer = cli_lex.Lexer()
        lexer.input(val)
        token = lexer.token()
        assert token.type == "NON_KEY"
        result = token.value
    return result


def is_classic_named_expr_present(expr):
    """
        Helper function to check that
        classic expression names present in the
        given expression or not.
        expr - Expression in which classic
           expression names need to be found.
        Returns True if classic named expression is present,
        otherwise returns False.
    """
    lexer = cli_lex.Lexer()
    lexer.input(expr)
    classic_expr_info_list = []
    while True:
        next_token = lexer.adv_expr_token()
        if not next_token:
            break
        token_value = str(next_token)
        if token_value in NamedExpression.built_in_named_expr:
            return True
        elif token_value in classic_entities_names:
            return True
    return False

class CheckConfig(object):
    """Base class to check the config"""

    @staticmethod
    def check_pos_expr(commandParseTree, pos):
        """
            Check the expression present at a given position
            commandParseTree - the parse tree to modify
            pos - the position of the parameter to modify
            If the expression is classic, then invalid
            flag would be set.
        """
        rule_node = commandParseTree.positional_value(pos)
        rule_expr = rule_node.value
        converted_expr = check_classic_expr.check_classic_expr(rule_expr)
        if converted_expr is None:
            logging.error('Error in checking command : ' +
                          str(commandParseTree))
        else:
            # converted_expr will have quotes and rule_expr will not have
            # quotes. Since we are comparing these 2 expressions, removing
            # quotes from converted_expr.
            converted_expr = remove_quotes(converted_expr)
            if converted_expr != rule_expr:
                # expression is converted, this is classic.
                commandParseTree.set_invalid()
            if is_classic_named_expr_present(converted_expr):
                commandParseTree.set_invalid()
        return commandParseTree

    @staticmethod
    def check_keyword_expr(commandParseTree, keywordName):
        """
            Check the expression present as a value of
            the given keyword name.
            commandParseTree - the parse tree to modify
            keywordName - the name of the keyword parameter to modify
            If the expression is classic, then invalid
            flag would be set.
        """
        if not commandParseTree.keyword_exists(keywordName):
            return commandParseTree
        rule_node = commandParseTree.keyword_value(keywordName)
        rule_expr = rule_node[0].value
        converted_expr = check_classic_expr.check_classic_expr(rule_expr)
        if converted_expr is None:
            logging.error('Error in checking command : ' +
                          str(commandParseTree))
        else:
            # converted_expr will have quotes and rule_expr will not have
            # quotes. Since we are comparing these 2 expressions, removing
            # quotes from converted_expr.
            converted_expr = remove_quotes(converted_expr)
            if converted_expr != rule_expr:
                # expression is converted, this is classic.
                commandParseTree.set_invalid()
            if is_classic_named_expr_present(converted_expr):
                commandParseTree.set_invalid()
        return commandParseTree

    @staticmethod
    def register_policy_entity_name(commandParseTree):
        """ Add the entity name in the global list."""
        name = commandParseTree.positional_value(0).value.lower()
        policy_entities_names.add(name)

    @staticmethod
    def register_classic_entity_name(commandParseTree):
        """ Add the classic entity name in the classic global list."""
        name = commandParseTree.positional_value(0).value.lower()
        classic_entities_names.add(name)


@common.register_class_methods
class CacheRedirection(CheckConfig):
    """ Handle CR feature """

    # Classic built-in policy names
    built_in_policies = [
        "bypass-non-get",
        "bypass-cache-control",
        "bypass-dynamic-url",
        "bypass-urltokens",
        "bypass-cookie"
    ]


    @common.register_for_cmd("add", "cr", "policy")
    def check_policy(self, commandParseTree):
        """
        Checks classic CR policy.
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        """
        If action field is not set, then it is classic policy,
        else it is an advanced policy.
        """
        if commandParseTree.keyword_exists('action'):
            return []
        else:
            return [commandParseTree]

    @common.register_for_cmd("bind", "cr", "vserver")
    def check_cr_vserver_bind(self, bind_parse_tree):
        """
        Handles CR vserver bind command.
        bind cr vserver <name> -policyName <string>
        -priority <positive_integer> -gotoPriorityExpression <expression>
        """
        if not bind_parse_tree.keyword_exists('policyName'):
            return []

        policy_name = bind_parse_tree.keyword_value("policyName")[0].value
        class_name = self.__class__.__name__
        policy_type = common.pols_binds.get_policy(policy_name).module
        # When policy is CR policy.
        if policy_type == class_name:
            # check for classic built-in policy.
            if policy_name in self.built_in_policies:
                return [bind_parse_tree]

        return []


@common.register_class_methods
class SSL(CheckConfig):
    """ Handle SSL feature """

    @common.register_for_cmd("add", "ssl", "policy")
    def check_policy(self, commandParseTree):
        """
        Check classic SSL policy.
        """

        commandParseTree = SSL.check_keyword_expr(commandParseTree, 'rule')
        if commandParseTree.invalid:
            return [commandParseTree]
        return []


@common.register_class_methods
class APPFw(CheckConfig):
    """ Handle APPFw feature """

    @common.register_for_cmd("add", "appfw", "policy")
    def check_policy(self, commandParseTree):
        """
        Check classic AppFw policy
        """
        commandParseTree = APPFw.check_pos_expr(commandParseTree, 1)
        if commandParseTree.invalid:
            return [commandParseTree]
        return []


@common.register_class_methods
class Patset(CheckConfig):
    """ Patset entity """

    @common.register_for_cmd("add", "policy", "patset")
    def register_name(self, commandParseTree):
        Patset.register_policy_entity_name(commandParseTree)
        if commandParseTree.keyword_exists('indexType'):
            return [commandParseTree]
        return []


@common.register_class_methods
class Dataset(CheckConfig):
    """ Dataset entity """

    @common.register_for_cmd("add", "policy", "dataset")
    def register_name(self, commandParseTree):
        Dataset.register_policy_entity_name(commandParseTree)
        if commandParseTree.keyword_exists('indexType'):
            return [commandParseTree]
        return []


@common.register_class_methods
class HTTP_CALLOUT(CheckConfig):
    """ HTTP callout entity """

    @common.register_for_cmd("add", "policy", "httpCallout")
    def register_name(self, commandParseTree):
        HTTP_CALLOUT.register_policy_entity_name(commandParseTree)
        return []


@common.register_class_methods
class StringMap(CheckConfig):
    """ String map entity """

    @common.register_for_cmd("add", "policy", "stringmap")
    def register_name(self, commandParseTree):
        StringMap.register_policy_entity_name(commandParseTree)
        return []


@common.register_class_methods
class NSVariable(CheckConfig):
    """ NS Variable entity """

    @common.register_for_cmd("add", "ns", "variable")
    def register_name(self, commandParseTree):
        NSVariable.register_policy_entity_name(commandParseTree)
        return []


@common.register_class_methods
class EncryptionKey(CheckConfig):
    """ Encryption key entity """

    @common.register_for_cmd("add", "ns", "encryptionKey")
    def register_name(self, commandParseTree):
        EncryptionKey.register_policy_entity_name(commandParseTree)
        return []


@common.register_class_methods
class HMACKey(CheckConfig):
    """ HMAC key entity """

    @common.register_for_cmd("add", "ns", "hmacKey")
    def register_name(self, commandParseTree):
        HMACKey.register_policy_entity_name(commandParseTree)
        return []


@common.register_class_methods
class NamedExpression(CheckConfig):
    """ Handle Named expression feature """

    # Built-in classic named expression names
    built_in_named_expr = {
        "ns_true",
        "ns_false",
        "ns_non_get",
        "ns_cachecontrol_nostore",
        "ns_cachecontrol_nocache",
        "ns_header_pragma",
        "ns_header_cookie",
        "ns_ext_cgi",
        "ns_ext_asp",
        "ns_ext_exe",
        "ns_ext_cfm",
        "ns_ext_ex",
        "ns_ext_shtml",
        "ns_ext_htx",
        "ns_url_path_cgibin",
        "ns_url_path_exec",
        "ns_url_path_bin",
        "ns_url_tokens",
        "ns_ext_not_gif",
        "ns_ext_not_jpeg",
        "ns_cmpclient",
        "ns_slowclient",
        "ns_content_type",
        "ns_msword",
        "ns_msexcel",
        "ns_msppt",
        "ns_css",
        "ns_xmldata",
        "ns_mozilla_47",
        "ns_msie"
    }

    @staticmethod
    def register_built_in_named_exprs():
        """
        Register built-in classic Named expression names in
        classic_entities_names.
        """
        for classic_exp_name in NamedExpression.built_in_named_expr:
            classic_entities_names.add(classic_exp_name)

    @common.register_for_cmd("add", "policy", "expression")
    def check_policy_expr(self, commandParseTree):
        """
            Classic named expression name is not
            valid for advanced expression if:
            1. It the name is same as one of the Policy
               entity (patset/dataset/stringmap/
               variable/hmacKey/EncriptionKey/callout) name.
            2. it doesn't start with ASCII alphabetic character or underscore.
            3. it has characters other than ASCII alphanumerics
               or underscore characters.
            4. it is equal to a advanced policy expression reserved word (prefix identifier or
               enum value)
        """
        reserved_word_list = set(
            [ # Advanced policy expression prefix list
             "subscriber",
             "connection",
             "analytics",
             "diameter",
             "target",
             "server",
             "radius",
             "oracle",
             "extend",
             "client",
             "mysql",
             "mssql",
             "false",
             "true",
             "text",
             "smpp",
             "icap",
             "http",
             "url",
             "sys",
             "sip",
             "ica",
             "dns",
             "aaa",
             "re",
             "xp",
             "ce"
             ])

        expr_name = commandParseTree.positional_value(0).value
        expr_rule = commandParseTree.positional_value(1).value
        named_expr[expr_name] = expr_rule
        lower_expr_name = expr_name.lower()
        if (((lower_expr_name in reserved_word_list) or
             (re.match('^[a-z_][a-z0-9_]*$', lower_expr_name) is None) or
             (lower_expr_name in policy_entities_names))):
            logging.error(("Expression name {} is invalid for advanced "
                           "expression: names must begin with an ASCII "
                           "alphabetic character or underscore and must "
                           "contain only ASCII alphanumerics or underscores"
                           " and shouldn't be name of another policy entity"
                           "; words reserved for policy use may not be used;"
                           " underscores will be substituted for any invalid"
                           " characters in corresponding advanced name")
                          .format(expr_name))

        if commandParseTree.keyword_exists('clientSecurityMessage'):
            NamedExpression.register_classic_entity_name(commandParseTree)
            return []

        original_tree = copy.deepcopy(commandParseTree)
        commandParseTree = NamedExpression \
            .check_pos_expr(commandParseTree, 1)

        if commandParseTree.invalid:
            """
            Add the commands in the global list which will be used to
            check whether any other expression is using these named
            expressions.
            """
            NamedExpression.register_policy_entity_name(commandParseTree)
            NamedExpression.register_classic_entity_name(original_tree)
        else:
            NamedExpression.register_policy_entity_name(original_tree)
        return []


@common.register_class_methods
class HTTPProfile(CheckConfig):
    """ Handle HTTP Profile """

    @common.register_for_cmd("add", "ns", "httpProfile")
    @common.register_for_cmd("set", "ns", "httpProfile")
    def check_spdy(self, commandParseTree):
        """
        Check if spdy parameter present in HTTP profile.
        Syntax:
        """
        if commandParseTree.keyword_exists('spdy'):
            return [commandParseTree]
        return []


@common.register_class_methods
class ContentSwitching(CheckConfig):
    """ Check Content Switching feature """

    @common.register_for_cmd("add", "cs", "policy")
    def check_cs_policy(self, commandParseTree):
        if commandParseTree.keyword_exists('action'):
            return []
        if commandParseTree.keyword_exists('rule'):
            if commandParseTree.keyword_exists('domain'):
                    return [commandParseTree]
            else:
                original_cmd = copy.deepcopy(commandParseTree)
                commandParseTree = ContentSwitching \
                    .check_keyword_expr(commandParseTree, 'rule')
                if commandParseTree.invalid:
                    return [original_cmd]
        elif commandParseTree.keyword_exists('url'):
            return [commandParseTree]
        elif commandParseTree.keyword_exists('domain'):
            return [commandParseTree]

        return []


@common.register_class_methods
class CMP(CheckConfig):
    """
    Checks CMP feature commands.
    """

    # Classic built-in policy names.
    built_in_policies = [
        "ns_cmp_content_type",
        "ns_cmp_msapp",
        "ns_cmp_mscss",
        "ns_nocmp_mozilla_47",
        "ns_nocmp_xml_ie"
    ]

    @common.register_for_cmd("set", "cmp", "parameter")
    def set_cmp_parameter(self, cmp_param_tree):
        if cmp_param_tree.keyword_exists("policyType"):
            self._initial_cmp_parameter = \
                cmp_param_tree.keyword_value("policyType")[0].value.lower()
            if self._initial_cmp_parameter == "classic":
                return [cmp_param_tree]
        return []

    @common.register_for_cmd("set", "cmp", "policy")
    def set_cmp_policy(self, cmp_policy_tree):
        policy_name = cmp_policy_tree.positional_value(0).value
        if policy_name in self.built_in_policies:
            return [cmp_policy_tree]
        return []

    @common.register_for_cmd("add", "cmp", "policy")
    def check_cmp_policy(self, cmp_policy_tree):
        original_cmd = copy.deepcopy(cmp_policy_tree)
        CheckConfig.check_keyword_expr(cmp_policy_tree, 'rule')
        if cmp_policy_tree.invalid:
            return [original_cmd]
        return []

    @common.register_for_cmd("bind", "cmp", "global")
    def check_cmp_global_bind(self, bind_cmd_tree):
        """
        Checks CMP policy bindings to cmp global.
        """
        # If state keyword is present then it is a
        # classic binding.
        if bind_cmd_tree.keyword_exists("state"):
            return [bind_cmd_tree]

        policy_name = bind_cmd_tree.positional_value(0).value
        if policy_name in self.built_in_policies:
            return [bind_cmd_tree]
        return []


@common.register_class_methods
class CLITransformFilter(CheckConfig):
    """
    Checks Filter feature
    """

    @common.register_for_cmd("add", "filter", "action")
    def check_filter_action(self, action_parse_tree):
        """
        Check Filter action
        """
        return [action_parse_tree]

    @common.register_for_cmd("add", "filter", "policy")
    def check_filter_policy(self, policy_parse_tree):
        """
        Check Filter policy
        """
        return [policy_parse_tree]

    @common.register_for_cmd("bind", "filter", "global")
    def check_filter_global_bindings(self, bind_parse_tree):
        """
        Check Filter global binding
        """
        return [bind_parse_tree]

    @common.register_for_cmd("add", "filter", "htmlinjectionvariable")
    @common.register_for_cmd("set", "filter", "htmlinjectionvariable")
    @common.register_for_cmd("set", "filter", "htmlinjectionparameter")
    @common.register_for_cmd("set", "filter", "prebodyInjection")
    @common.register_for_cmd("set", "filter", "postbodyInjection")
    def check_filter_htmlinjection_command(self, cmd_parse_tree):
        """
        Check Filter HTMLInjection command
        """
        return [cmd_parse_tree]


@common.register_class_methods
class Rewrite(CheckConfig):
    """
    Check rewrite action
    """

    @common.register_for_cmd("add", "rewrite", "action")
    def check_rewrite_action(self, tree):
        if tree.keyword_exists('pattern'):
            return [tree]
        if tree.keyword_exists('bypassSafetyCheck'):
            return [tree]
        return []


@common.register_class_methods
class LB(CheckConfig):
    """
    Check LB persistence rule
    """

    @common.register_for_cmd("add", "lb", "vserver")
    def check_rewrite_action(self, commandParseTree):
        commandParseTree = LB.check_keyword_expr(commandParseTree, 'rule')
        if commandParseTree.invalid:
            return [commandParseTree]
        return []


@common.register_class_methods
class SureConnect(CheckConfig):
    """
    Check SureConnect commands
    """

    @common.register_for_cmd("add", "sc", "policy")
    @common.register_for_cmd("set", "sc", "parameter")
    def check_sc_policy(self, tree):
        return [tree]


@common.register_class_methods
class PriorityQueuing(CheckConfig):
    """
    Check PriorityQueuing commands
    """

    @common.register_for_cmd("add", "pq", "policy")
    def check_sc_policy(self, tree):
        return [tree]


@common.register_class_methods
class HDoSP(CheckConfig):
    """
    Check HTTP Denial of Service Protection commands
    """

    @common.register_for_cmd("add", "dos", "policy")
    def check_sc_policy(self, tree):
        return [tree]
