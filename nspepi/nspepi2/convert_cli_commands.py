#!/usr/bin/env python

# Copyright 2021-2022 Citrix Systems, Inc. All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import collections
import copy

import cli_lex
import nspepi_common as common
import convert_classic_expr
from nspepi_parse_tree import *

# All module names starting with "convert_" are parsed to detect and register
# class methods


def convert_cli_init():
    """Initialize global variables uses by this module"""
    global vserver_protocol_dict
    vserver_protocol_dict = OrderedDict()
    global policy_entities_names
    global classic_entities_names
    global named_expr
    named_expr = {}
    policy_entities_names = set()
    classic_entities_names = set()
    # Register built-in named expressions.
    NamedExpression.register_built_in_named_exprs()
    global cli_global_binds
    global cli_vserver_binds
    global cli_user_binds
    global cli_group_binds
    global cli_service_binds
    cli_global_binds = OrderedDict()
    cli_vserver_binds = OrderedDict()
    cli_user_binds = OrderedDict()
    cli_group_binds = OrderedDict()
    cli_service_binds = OrderedDict()


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


def get_advanced_name(classic_name):
    """
        Helper function to get a valid Advanced identifier
        corresponding to a Classic identifier.
        Note that this does not deal with reserved words.
        Nor does it check for duplicates.
    """
    adv_name = "nspepi_adv_" + re.sub(r'[^a-zA-Z0-9_]', '_', classic_name)
    return adv_name


def get_classic_expr_list(expr):
    """
        Helper function to get the list of
        classic expression names present in the
        given expression.
        expr - Expression in which classic
           expression names need to be found.
        Returns the list of items found or None if none;
        the items are each a list with:
            - classic expression name
            - advanced expression name
            - start offset of token to replace
            - length of token to replace
    """
    lexer = cli_lex.Lexer()
    lexer.input(expr)
    classic_expr_info_list = []
    while True:
        next_token = lexer.adv_expr_token()
        if not next_token:
            break
        token_value = str(next_token)
        token_value_len = len(token_value)
        is_classic_expr = False
        if token_value in NamedExpression.built_in_named_expr:
            # Checking for built-in classic Named expression.
            adv_expr_name = NamedExpression.built_in_named_expr[token_value]
            lower_adv_expr_name = adv_expr_name.lower()
            if lower_adv_expr_name in policy_entities_names:
                is_classic_expr = True
        else:
            adv_expr_name = get_advanced_name(token_value)
            if (adv_expr_name.lower() not in policy_entities_names):
                if token_value.lower() in classic_entities_names:
                    adv_expr_name = None
                    is_classic_expr = True
            else:
                is_classic_expr = True
        if (next_token.type == "IDENTIFIER" and is_classic_expr):
            start_offset = next_token.lexpos - token_value_len + 1
            expr_info = [token_value, adv_expr_name,
                         start_offset, token_value_len]
            classic_expr_info_list.append(expr_info)

    return classic_expr_info_list


def has_client_security_expressions(expr):
    """
        Helper function to check that named
        expressions configured with clientSecurityMessage
        parameter are present in the given expression.
        expr - Expression in which named
           expressions need to be found.
        Returns True and named expression list if the
        named expressions configured with clientSecurityMessage
        are present in the given expression, otherwise returns False
        and empty named expression list.
    """
    expr_list = get_classic_expr_list(expr)
    csec_expr_list = []
    for expr_info in expr_list:
        expr_name = expr_info[0].lower()
        if expr_name in NamedExpression.csec_expr_list:
            csec_expr_list.append(expr_name)
            return ([True, csec_expr_list])

    return ([False, csec_expr_list])


def print_csec_error_message(expr_list):
    """
       Print the Error for those named expressions
       which are configured with clientSecurityMessage
       parameter.
    """
    for expr_name in expr_list:
        if not NamedExpression.csec_expr_list[expr_name]["error_displayed"]:
            logging.error(("Conversion of clientSecurityMessage based expression [{}] "
                           "is not supported, please do the conversion manually.")
                           .format(str(NamedExpression.csec_expr_list[expr_name]["tree"]).strip()))
            NamedExpression.csec_expr_list[expr_name]["error_displayed"] = True


class ConvertConfig(object):
    """Base class to convert the config"""

    @staticmethod
    def replace_named_expr(rule_expr):
        """
           Helper function to replace the classic named
           expression with the advanced named expression
           in the given expression.
           rule_expr - the expression to modify
           Returns the expression with names modified as needed.
        """
        converted_expr = rule_expr
        for expr_info in reversed(get_classic_expr_list(rule_expr)):
            # Work in reverse order to avoid recomputing offsets
            if expr_info[1] is None:
                return None
            offset = expr_info[2]
            replace_len = expr_info[3]
            converted_expr = (converted_expr[0: offset] +
                              expr_info[1] + converted_expr[offset +
                              replace_len:])

        return converted_expr

    @staticmethod
    def convert_pos_expr(commandParseTree, pos):
        """
            Convert the expression present at a given position
            commandParseTree - the parse tree to modify
            pos - the position of the parameter to modify
            Returns the modified parse tree.
        """
        rule_node = commandParseTree.positional_value(pos)
        rule_expr = rule_node.value

        csec_expr_info = has_client_security_expressions(rule_expr)
        if csec_expr_info[0]:
            print_csec_error_message(csec_expr_info[1])
            logging.error('Error in converting command : ' +
                          str(commandParseTree).strp())
            return commandParseTree

        converted_expr = convert_classic_expr.convert_classic_expr(rule_expr)
        if converted_expr is None:
            logging.error('Error in converting command : ' +
                          str(commandParseTree).strip())
            converted_expr = rule_expr
        else:
            # converted_expr will have quotes and rule_expr will not have
            # quotes. Since we are comparing these 2 expressions, removing
            # quotes from converted_expr.
            converted_expr = remove_quotes(converted_expr)
            if converted_expr != rule_expr:
                # expression is converted, this is classic.
                rule_node.set_value(converted_expr)
                commandParseTree.set_upgraded()
            else:
                # expression is not converted, then it can be advanced
                # expression. Advanced expressions can have Q and S prefixes and
                # SYS.EVAL_CLASSIC_EXPR expression which needs to be converted.
                commandParseTree = ConvertConfig \
                    .convert_adv_expr_list(commandParseTree, [pos])
        return commandParseTree

    @staticmethod
    def convert_keyword_expr(commandParseTree, keywordName):
        """
            Convert the expression present as a value of
            the given keyword name.
            commandParseTree - the parse tree to modify
            keywordName - the name of the keyword parameter to modify
            Returns the modified parse tree.
        """
        rule_node = commandParseTree.keyword_value(keywordName)
        rule_expr = rule_node[0].value

        csec_expr_info = has_client_security_expressions(rule_expr)
        if csec_expr_info[0]:
            print_csec_error_message(csec_expr_info[1])
            logging.error('Error in converting command : ' +
                          str(commandParseTree).strip())
            return commandParseTree

        converted_expr = convert_classic_expr.convert_classic_expr(rule_expr)
        if converted_expr is None:
            logging.error('Error in converting command : ' +
                          str(commandParseTree).strip())
            converted_expr = rule_expr
        else:
            # converted_expr will have quotes and rule_expr will not have
            # quotes. Since we are comparing these 2 expressions, removing
            # quotes from converted_expr.
            converted_expr = remove_quotes(converted_expr)
            if converted_expr != rule_expr:
                # expression is converted, this is classic.
                rule_node[0].set_value(converted_expr)
                commandParseTree.set_upgraded()
            else:
                # expression is not converted, then it can be advanced
                # expression. Advanced expressions can have Q and S prefixes and
                # SYS.EVAL_CLASSIC_EXPR expression which needs to be converted.
                commandParseTree = ConvertConfig \
                    .convert_adv_expr_list(commandParseTree, [keywordName])
        return commandParseTree

    @staticmethod
    def convert_adv_expr_list(tree, param_list):
        """
        Converts Q and S prefixes and SYS.EVAL_CLASSIC_EXPR expression from the given
        list of parameters.
        tree - the parse tree to modify
        param_list - list of parameters to modify. Each Parameter can be either
                     positional parameter or keyword parameter.
                     If its a keyword parameter, mention the keyword name.
                     If its a positional parameter, mention the position of
                     the parameter.
        Returns the modified parse tree.
        """
        original_tree = copy.deepcopy(tree)
        for param in param_list:
            adv_expr = common.get_cmd_arg(param, tree)
            if adv_expr is None:
                continue
            converted_expr = convert_classic_expr.convert_adv_expr(adv_expr)
            if converted_expr is None:
                logging.error('Error in converting command : ' +
                              str(original_tree).strip())
                return original_tree
            else:
                converted_expr = remove_quotes(converted_expr)
                if converted_expr != adv_expr:
                    if isinstance(param, int):
                        # Positional Parameter
                        tree.positional_value(param).set_value(converted_expr)
                    else:
                        # Keyword Parameter
                        tree.keyword_value(param)[0].set_value(converted_expr)
                    tree.set_adv_upgraded()
        return tree

    def store_builtin_policies(self):
        """
        Creates and stores Policy object for built-in policies.
        """
        # Since built-in policy add commands are not saved
        # in ns.conf, function registered for add commands will
        # not be called for built-in policies where policy object
        # is stored.
        for policy_name in self.built_in_policies:
            pol_obj = common.Policy(policy_name, self.__class__.__name__,
                                    "classic")
            common.pols_binds.store_policy(pol_obj)
            pol_obj = common.Policy(self.built_in_policies[policy_name],
                                    self.__class__.__name__, "advanced")
            common.pols_binds.store_policy(pol_obj)

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

    """
    POLICY BIND CONVERSION INFRASTRUCTURE
    Converting binds of classic policies to the equivalent advanced
    policies has a number of issues to address:

    1. There can be multiple classic policies bound to same priority
       and classic policies can be bound without priority also.
       The equivalent advanced policies must be bound at separate
       policies that maintain the original order.

    2. Binds for policies for classic modules that are being replaced
       by an advanced module (e.g. Filter by Rewrite and Responder)
       may need to be inserted before or after existing policy binds
       to maintain the same order of evaluation.

    Use of this infrastructure for a module

    1. Each module class must be a subclass of ConvertConfig to inherit
       the infrastructure methods and attributes.

    2. If the bind command does not have gotoPriorityExpression,
       then it uses the default gotoPriorityExpression of END.
       If the module class does not want to use the default value, then
       the module class must override the bind_default_goto attribute.
       If the module class does not want to add gotoPriorityExpression
       to bind command, then override the bind_default_goto attribute
       with None.

    3. If priority and gotopriorityexpression are positional arguments
       in the bind command and if the bind command does not have these values
       initially and the binding infra is used to add a priority and default
       goto value then, priority and gotopriorityexpression will
       be added at the end of the positional arguments list.
       example:
           bind <module> global <policyname>
           converts to
           bind <module> global <policyname> <priority> <goto>

    4. Each parsed bind command is processed by either:

           <module_obj>.convert_global_bind(parse_tree, module, priority_arg,
                                       goto_arg, position)
       or
           <module_obj>.convert_entity_policy_bind(parse_tree,
                           policy_module, priority_arg, goto_arg, position)


       These methods save bind commands in the appropriate dictionaries.
       These methods can be used for bindings of policies to
       global/vserver/user/group/service.
    """

    class BindInfo(object):
        """
        Object to hold the bind command info.
        """
        def __init__(self):
            """
            Bind command information.
            orig_cmd   - original bind command read from config.
            parse_tree - bind command parse tree.
            position   - position where the bind command
                         has to be inserted. Possible
                         values - before, inplace, after.
            priority   - priority value.
            goto       - gotopriorityexpression value.
            bind_arg_priority - Provides the positional index
                                or keyword name for the priority
                                parameter.
            bind_arg_goto - Provides the positional index or
                            keyword name for the goto parameter.
            policy_type - type of policy("classic" or "advanced")
            flow_type_direction - bind type information("REQUEST" or
                             "RESPONSE")
            """
            self.orig_cmd = ""
            self.parse_tree = None
            self.position = ""    # "before", "inplace", or "after" insertion
            self.priority = 0
            self.goto = ""
            self.bind_arg_priority = "priority"
            self.bind_arg_goto = "gotoPriorityExpression"
            self.policy_type = None
            self.flow_type_direction = None

        def set(self, orig_cmd, parse_tree, position, priority, goto,
                priority_arg, goto_arg, policy_type, flow_type_direction):
            """
            Sets the BindInfo class instance variables.
            orig_cmd   - original bind command read from config.
            parse_tree - bind comman parse tree.
            position   - position of insertion.
            priority   - priority
            goto       - gotopriorityexpression value.
            priority_arg - Positional index or keyword name
                           for the priority argument.
            goto_arg - positional index or keyword name
                       for the goto argument.
            flow_type_direction - bind type information( "REQUEST"
                                  or "RESPONSE")
            """
            self.orig_cmd = orig_cmd
            self.parse_tree = parse_tree
            self.position = position
            self.priority = priority
            self.goto = goto
            self.bind_arg_priority = priority_arg
            self.bind_arg_goto = goto_arg
            self.policy_type = policy_type
            self.flow_type_direction = flow_type_direction

    def get_bind_dict(self, current_dict, key):
        """
        Return the dictionary selected by key in current_dict. If
        this dictionary does not yet exist, it will be created.
        current_dict - dictionary
        key          - key name
        """
        if key not in current_dict:
            current_dict[key] = OrderedDict()
        return current_dict[key]

    def save_bind_for_reprioritization_common(self, bind_dict, orig_tree, tree,
                                              position, priority, goto,
                                              bind_type, priority_arg,
                                              goto_arg, policy_type):
        """
        Save a bind command in the relevant dictionary for later processing
        bind_dict - is a dictionary which has list of
                    BindInfo objects for commands for a bindpoint
                    (e.g. GLOBAL REWRITE REQ_DEFAULT). A BindInfo
                    object for the current command will be appended
                    to the list.
        orig_tree - parsed command tree of bind command read from config.
        tree - processed and possibly modified command tree of bind command.
        position - indicates where the bind is to be inserted:
                   "before", "inplace", or "after".
        priority - is the bind prority as an int; may be 0.
        goto -  is the gotoPriorityExpression for the bind
        bind_type - is the type arg e.g. "REQ_DEFAULT"
        priority_arg - Positional index or keyword name
                       for the priority argument.
        goto_arg - Positional index or keyword name
                   for the goto argument.
        """
        # bind_type may be None in some cases.
        # bind_type is used as key for dictionary,
        # so making the bind_type equal to empty string
        # when the bind_type is None.
        if bind_type is None:
            bind_type = ""
        else:
            bind_type = bind_type.lower()
        if bind_type not in bind_dict:
            bind_dict[bind_type] = []
        bind_info = self.BindInfo()
        flow_type_direction = self.flow_type_direction_default
        bind_info.set(orig_tree.original_line, tree, position, int(priority),
                      goto, priority_arg, goto_arg,
                      policy_type, flow_type_direction)
        bind_dict[bind_type].append(bind_info)

    def update_tree_arg(self, tree, arg, value):
        """
        Modifies the parse tree argument. If arg is string it
        is a keyword. If arg is an int it is a positional index.
        For positional index:
            Updates the positional value if the positional value
            already exists.
            If positional argument arg is not present, then
            adds positional argument with value.
        For keyword argument:
            Updated the keyword value, if keyword already exists
            else adds a keyword to tree with keyword name arg and
            keyword value value
        If value is None, argument is not added.
        tree - Command parse tree.
        arg  - Command argument, Can be positional or keyword.
        value - command argument value.
        """
        if value is None:
            return
        if isinstance(arg, int):
            if tree.positional_value(arg) is not None:
                tree.positional_value(arg).set_value(value)
            else:
                pos = CLIPositionalParameter(value)
                tree.add_positional(pos)
        else:
            if tree.keyword_exists(arg):
                tree.keyword_value(arg)[0].set_value(value)
            else:
                keyword_arg = CLIKeywordParameter(CLIKeywordName(arg))
                keyword_arg.add_value(value)
                tree.add_keyword(keyword_arg)
        tree.set_upgraded()

    """
    The gotoPriorityExpression argument to use for converted bindings.
    Override in a module class if different.
    If gotoPriorityExpression argument is not required, then override
    with None.
    """
    bind_default_goto = "END"

    """
    The bind type side(REQUEST or RESPONSE) information used to
    add -type keyword in converted bindings.
    Override in a module class if different.
    If -type keyword is not required, then override with None.
    """
    flow_type_direction_default = "REQUEST"

    def convert_global_bind(self, orig_tree, tree, policy_name, module,
                            priority_arg, goto_arg, position="inplace"):
        """
        Process a global bind command represented by
        the command parse tree and saves the required info:
            bind <module> global <other arguments>
        Save the bind command in the cli_global_binds dictionary. Return empty
        list to delete the command. It will later be emitted after
        reprioritization.
        The dictionary path:
            cli_global_binds[<module>][<bind_type>]
        Args:
        orig_tree - bind command parse tree of original command from ns.conf.
                    In case bind command is created newly then this argument
                    should contain the bind command parse tree of original
                    command from which this new bind command is getting
                    created
        tree  - bind command parse tree.
        policy_name - name of the policy that is bound in this bind command
        module - Name of the policy module(e.g. appfw, tunnel)
        priority_arg - identification of the parameter in the bind command
                       for priority
        goto_arg - identification of the parameter in the bind command for goto
        position - position to be inserted.
        """
        if position not in ("before", "inplace", "after"):
            logging.critical("unexpected insert position value")
            sys.exit()
        priority, goto, bind_type = self.get_common_info(tree,
                                                         priority_arg,
                                                         goto_arg)
        # get policy type
        policy_type = None
        if policy_name in common.pols_binds.policies:
            policy_type = common.pols_binds.policies[policy_name].policy_type
        bind_dict = self.get_bind_dict(cli_global_binds, module.lower())
        self.save_bind_for_reprioritization_common(bind_dict, orig_tree, tree,
                                                   position, priority, goto,
                                                   bind_type, priority_arg,
                                                   goto_arg, policy_type)
        # store original bind command for analysis
        common.pols_binds.store_original_bind(
            common.Bind(
                "global", orig_tree.ot.lower(), None, policy_name,
                module.lower(), bind_type if bind_type else "", str(priority),
                orig_tree.original_line, lineno=orig_tree.lineno))
        return []

    def convert_entity_policy_bind(self, orig_tree, tree, policy_name,
                                   policy_module, priority_arg, goto_arg,
                                   position="inplace"):
        """
        Process a vserver/user/group/service bind command
        represented by the command parse tree:
            bind <vserver_type> vserver <vserver_name> <other arguments>
            bind <user_type> user <userName> <other arguments>
            bind <group_type> group <groupName> <other arguments>
            bind <service_type> service <serviceName> <other arguments>
        Save the bind command in the cli_vserver_binds/cli_user_binds/
        cli_group_binds/cli_service_binds dictionary. Return an empty
        parse tree to delete the command. It will later be emitted after
        reprioritization.
        The dictionary path:
            cli_vserver_binds[<vserver_type>][<vserver_name>][<module>][<bind_type>]
            cli_user_binds[<user_type>][<user_name>][<module>][<bind_type>]
            cli_group_binds[<group_type>][<group_name>][<module>][<bind_type>]
            cli_service_binds[<service_type>][<service_name>][<module>][<bind_type>]
        orig_tree - bind command parse tree of original command from ns.conf.
                    In case bind command is created newly then this argument
                    should contain the bind command parse tree of original
                    command from which this new bind command is getting
                    created
        tree - bind command parse tree.
        policy_name - name of the policy that is bound in this bind command
        policy_module - module name of policy which is
                        bound to the bind command.
        priority_arg - identification of the parameter in the bind command
                       for priority
        goto_arg - identification of the parameter in the bind command for goto
        position - position to be inserted.
        """
        if position not in ("before", "inplace", "after"):
            logging.critical("unexpected insert position value")
            sys.exit()
        entity = tree.ot.lower()
        entity_type = tree.group
        entity_name = common.get_cmd_arg(0, tree)
        priority, goto, bind_type = self.get_common_info(tree, priority_arg,
                                                         goto_arg)
        policy_type = None
        # get policy type
        if policy_name in common.pols_binds.policies:
            policy_type = common.pols_binds.policies[policy_name].policy_type
        if entity == "vserver":
            bind_dict = self.get_bind_dict(cli_vserver_binds,
                                           entity_type.lower())
        elif entity == "user":
            bind_dict = self.get_bind_dict(cli_user_binds, entity_type.lower())
        elif entity == "group":
            bind_dict = self.get_bind_dict(cli_group_binds,
                                           entity_type.lower())
        elif entity == "service":
            bind_dict = self.get_bind_dict(cli_service_binds,
                                           entity_type.lower())
        else:
            logging.critical("Unexpected command " + str(tree))
            sys.exit()
        bind_dict = self.get_bind_dict(bind_dict, entity_name)
        bind_dict = self.get_bind_dict(bind_dict, policy_module.lower())
        self.save_bind_for_reprioritization_common(bind_dict, orig_tree, tree,
                                                   position, priority, goto,
                                                   bind_type, priority_arg,
                                                   goto_arg, policy_type)
        # store original bind command for analysis
        common.pols_binds.store_original_bind(
            common.Bind(
                entity, entity_type.lower(), entity_name, policy_name,
                policy_module.lower(), (bind_type if bind_type else ""),
                str(priority), orig_tree.original_line,
                lineno=orig_tree.lineno))
        return []

    def get_common_info(self, tree, priority_arg, goto_arg):
        """
        Returns priority, gotoPriorityExpression and
        bind type value from the parse tree.
        tree - parse tree
        """
        priority = common.get_cmd_arg(priority_arg, tree)
        if priority is None:
            priority = 0
            # Add priority argument to tree.
            self.update_tree_arg(tree, priority_arg, str(priority))
        else:
            priority = int(priority)

        goto = common.get_cmd_arg(goto_arg, tree)
        if goto is None:
            if self.bind_default_goto is not None:
                goto = self.bind_default_goto
                # Add goto argument to tree.
                self.update_tree_arg(tree, goto_arg, str(goto))

        bind_type = common.get_cmd_arg("type", tree)
        if bind_type is not None:
            if bind_type.lower() in ["req_default", "req_override"]:
                bind_type = "REQUEST"
            elif bind_type.lower() in ["res_default", "res_override"]:
                bind_type = "RESPONSE"
        return priority, goto, bind_type

    """
    Increment used when renumbering bind priorities.
    """
    PRIORITY_INCREMENT = 100

    def reprioritize_binds(self, binds):
        """
        Sort the binds for the bindpoint and if necessary renumber their
        priorities.
        - binds is a list of BindInfo objects
        Return a list of reprioritized BindInfo objects.
        """
        # Sort the binds by their positions.
        new_binds = []
        for position in ("before", "inplace", "after"):
            for bind_info in binds:
                if bind_info.position == position:
                    new_binds.append(bind_info)

        # Check if the bind priorities are not in the required order and so
        # require renumbering. Also 0 priorities require renumbering.
        need_pri_renum = False
        for i in range(len(new_binds)):
            if (new_binds[i].priority == 0) or ((i > 0) and
                                                (new_binds[i-1].priority
                                                 >= new_binds[i].priority)):
                need_pri_renum = True
                break

        if not need_pri_renum:
            return new_binds

        # Keep track of which old priority is mapped to which new priority,
        # for use in changing gotoPriorityExpressions. This needs to be done
        # separately for the before, inplace, and after binds, since there
        # can be duplicates priorities across these groups.
        old_to_new_pri = {}
        for position in ("before", "inplace", "after"):
            old_to_new_pri[position] = {}
        new_pri = self.PRIORITY_INCREMENT

        # Renumber the priorities in the binds.
        for bind_info in new_binds:
            old_to_new_pri[bind_info.position][bind_info.priority] = new_pri
            # Update priority in parse tree.
            self.update_tree_arg(bind_info.parse_tree,
                                 bind_info.bind_arg_priority, str(new_pri))
            new_pri += self.PRIORITY_INCREMENT

        # Check if any of the bind gotoPriorityExpressions have a priority
        # that needs to be modified. Also issue a error if any
        # gotoPriorityExpressions uses an expression.
        for bind_info in new_binds:
            goto = bind_info.goto
            if goto is None:
                continue
            elif goto.isdigit():
                old_goto = int(goto)
                max_goto = max(old_to_new_pri[bind_info.position])
                if old_goto in old_to_new_pri[bind_info.position]:
                    new_goto = str(old_to_new_pri[bind_info.position]
                                   [old_goto])
                elif old_goto > max_goto:
                    new_goto = "END"
                else:
                    new_goto = "1"
                # Update goto in parse tree.
                self.update_tree_arg(bind_info.parse_tree,
                                     bind_info.bind_arg_goto, new_goto)
            elif goto.upper() not in ("NEXT", "END", "USE_INVOCATION_RESULT"):
                logging.error("gotoPriorityExpression in {} uses an"
                              " expression. Since the priorities for this"
                              " bindpoint have been renumbered, this"
                              " expression will need to be modified manually."
                              "".format(str(bind_info.parse_tree)))
        return new_binds

    def reprioritize_and_emit_global_binds(self):
        """
        Renumber the priorities for policy binds to all global bindpoints
        and return a list of the command strings for those binds.
        """
        bind_cmd_trees = []
        for module in cli_global_binds:
            module_bind_dict = cli_global_binds[module]
            for bind_type in module_bind_dict:
                binds = module_bind_dict[bind_type]
                new_binds = self.reprioritize_binds(binds)
                for bind_info in new_binds:
                    if common.pols_binds.is_bind_unsupported(
                            bind_info.orig_cmd):
                        logging.error(
                            "Bind command [{}] is commented out because it"
                            " can't be converted to be under a valid advanced"
                            " bindpoint as priority needs to be changed"
                            " manually. However, the command is partially"
                            " converted as [{}]. If the command is required"
                            " please take a backup because comments are not"
                            " saved in ns.conf after triggering"
                            "'save ns config'.{}"
                            "".format(bind_info.orig_cmd.strip(),
                                      str(bind_info.parse_tree).strip(),
                                      common.CMD_MOD_ERR_MSG))
                        bind_cmd_trees.append(
                            "# {}".format(str(bind_info.parse_tree)))
                    else:
                        type_key_value = None
                        # Combine bind type side information and global_type
                        # information to determine the type keyword value.
                        # Possible values - REQ_DEFAULT, REQ_OVERRIDE,
                        #                   RES_DEFAULT, RES_OVERRIDE.
                        global_type = (
                            common.pols_binds.get_global_type_for_bind(
                                bind_info.orig_cmd))
                        if (bind_info.flow_type_direction and global_type and
                                bind_info.flow_type_direction in
                                ("REQUEST", "RESPONSE") and
                                bind_info.policy_type == "classic"):
                            type_key_value = (
                                bind_info.flow_type_direction[0:3]
                                + '_' + global_type)
                            self.update_tree_arg(
                                bind_info.parse_tree, "type",
                                type_key_value.upper())
                        if (module == "rewrite" and
                                bind_info.policy_type == "classic"):
                            type_key_value = (
                                bind_type[0:3] + '_' + global_type)
                            self.update_tree_arg(
                                bind_info.parse_tree, "type",
                                type_key_value.upper())
                        bind_cmd_trees.append(bind_info.parse_tree)
        return bind_cmd_trees

    def reprioritize_and_emit_4_level_dict(self, bind_dict):
        """
        Renumber the priorities for all policy binds in bind_dict
        and return a list of the command strings for those binds.
        bind_dict - dictionary in which parse trees are saved.
        dictionary path:
            bind_dict[<entity_type>][<entity_name>][<module>][<bind_type>]
        """
        bind_cmd_trees = []
        for entity_type in bind_dict:
            entity_type_bind_dict = bind_dict[entity_type]
            for entity_name in entity_type_bind_dict:
                entity_name_bind_dict = entity_type_bind_dict[entity_name]
                for module in entity_name_bind_dict:
                    module_bind_dict = entity_name_bind_dict[module]
                    for bind_type in module_bind_dict:
                        binds = module_bind_dict[bind_type]
                        new_binds = self.reprioritize_binds(binds)
                        for bind_info in new_binds:
                            if (bind_info.flow_type_direction and
                                    bind_info.policy_type == "classic"):
                                self.update_tree_arg(
                                    bind_info.parse_tree, "type",
                                    bind_info.flow_type_direction.upper())
                            if common.pols_binds.is_bind_unsupported(
                                    bind_info.orig_cmd):
                                logging.error(
                                    "Bind command [{}] is commented out"
                                    " because it can't be converted to be"
                                    " under a valid advanced bindpoint as"
                                    " priority needs to be changed manually."
                                    " However, the command is partially"
                                    " converted as [{}]. If the command is"
                                    " required please take a backup because"
                                    " comments are not saved in ns.conf"
                                    " after triggering 'save ns config'."
                                    "{}".format(
                                        bind_info.orig_cmd.strip(),
                                        str(bind_info.parse_tree).strip(),
                                        common.CMD_MOD_ERR_MSG))
                                bind_cmd_trees.append(
                                    "# {}".format(str(bind_info.parse_tree)))
                            else:
                                bind_cmd_trees.append(bind_info.parse_tree)
        return bind_cmd_trees

    def reprioritize_and_emit_binds(self):
        """
        Renumber the priorities for all policy binds
        and return a list of the command strings for those binds.
        """
        bind_cmd_trees = []
        bind_cmd_trees += self.reprioritize_and_emit_global_binds()
        bind_cmd_trees += \
            self.reprioritize_and_emit_4_level_dict(cli_vserver_binds)
        bind_cmd_trees += \
            self.reprioritize_and_emit_4_level_dict(cli_user_binds)
        bind_cmd_trees += \
            self.reprioritize_and_emit_4_level_dict(cli_group_binds)
        bind_cmd_trees += \
            self.reprioritize_and_emit_4_level_dict(cli_service_binds)
        return bind_cmd_trees


@common.register_class_methods
class CacheRedirection(ConvertConfig):
    """ Handle CR feature """

    # Classic built-in policy names and there corresponding
    # advanced built-in policy names.
    built_in_policies = {
        "bypass-non-get": "bypass-non-get-adv",
        "bypass-cache-control": "bypass-cache-control-adv",
        "bypass-dynamic-url": "bypass-dynamic-url-adv",
        "bypass-urltokens": "bypass-urltokens-adv",
        "bypass-cookie": "bypass-cookie-adv"
    }

    @common.register_for_init_call
    def store_builtin_cr_policies(self):
        """
        Creates and stores Policy object for built-in CR policies.
        """
        self.store_builtin_policies()

    @common.register_for_cmd("add", "cr", "vserver")
    def convert_cr_vserver(self, commandParseTree):
        """
        Get vserver protocol to help in filter bind conversion
        cr_protocol - cr vserver protocol
        crv_name - cr vserver name
        vserver_protocol_dict - dict to store protocol as value to the
                  vserver name as key
        """

        if commandParseTree.keyword_exists('td'):
            cr_protocol = str(commandParseTree.keyword_value('td')[1])
        else:
            cr_protocol = commandParseTree.positional_value(1).value

        crv_name = commandParseTree.positional_value(0).value
        vserver_protocol_dict[crv_name] = cr_protocol.upper()
        return [commandParseTree]

    @common.register_for_cmd("add", "cr", "policy")
    def convert_policy(self, commandParseTree):
        """
        Converts classic cr policy to advanced.
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        """Action can be set only with advance expression,
        so, only check for Q and S prefixes and sys.eval_classic_expr in
        the rule. If action field is not set, then convert the rule
        and set ORIGIN action."""
        if commandParseTree.keyword_exists('action'):
            commandParseTree = CacheRedirection \
                .convert_adv_expr_list(commandParseTree, ["rule"])
            return [commandParseTree]

        """Convert classic CR policy to advanced.
        Syntax:
        add cr policy -rule <classic rule>
        to
        add cr policy -rule <advance rule> -action ORIGIN"""
        commandParseTree = CacheRedirection \
            .convert_keyword_expr(commandParseTree, 'rule')
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        """If expression successfully converted into advanced,
        then only add action."""
        if commandParseTree.upgraded:
            action_node = CLIKeywordName('action')
            action_param = CLIKeywordParameter(action_node)
            action_param.add_value('ORIGIN')
            commandParseTree.add_keyword(action_param)
        return [commandParseTree]

    @common.register_for_cmd("bind", "cr", "vserver")
    def convert_cr_vserver_bind(self, bind_parse_tree):
        """
        Handles CR vserver bind command.
        bind cr vserver <name> -policyName <string>
        -priority <positive_integer> -gotoPriorityExpression <expression>
        """
        if not bind_parse_tree.keyword_exists('policyName'):
            return [bind_parse_tree]

        policy_name = bind_parse_tree.keyword_value("policyName")[0].value
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"

        class_name = self.__class__.__name__
        policy_type = common.pols_binds.get_policy(policy_name).module
        # When policy is CR policy.
        if policy_type == class_name:
            # check for classic built-in policy.
            if policy_name in self.built_in_policies:
                self.update_tree_arg(bind_parse_tree, "policyName",
                                     self.built_in_policies[policy_name])
            return self.convert_entity_policy_bind(
                bind_parse_tree, bind_parse_tree, policy_name,
                policy_type, priority_arg, goto_arg)

        """
        Calls the method that is registered for the particular
        policy type that is bound to CR. Returns converted_list.
        If the policy module is not registered for binding,
        then returns the original parse tree.
        """
        key = "CacheRedirection"
        if key in common.bind_table:
            if policy_type in common.bind_table[key]:
                m = common.bind_table[key][policy_type]
                return m.method(m.obj, bind_parse_tree, policy_name,
                                priority_arg, goto_arg)

        return [bind_parse_tree]


# TODO File based Classic Expressions do not have equivalent Advanced
# expressions. File based Classic Expressions can be used in Authorization
# policies. This may lead to some policies being converted and some not,
# which in overall will lead to invalid config. To avoid this issue,
# disabling the Classic Authorization policy and its bindings
# conversion for now.

# TODO The Advanced Authorization policies can have Q and S prefixes and
# SYS.EVAL_CLASSIC_EXPR expression which needs to be converted.
# Registering the authorization policy to convert_advanced_expr in AdvExpression
# class to support Advance expression conversion. While enabling back the Classic
# Authorization policy conversion, remove the entry from convert_advanced_expr.
#@common.register_class_methods
class Authorization(ConvertConfig):
    """ Handle Authorization feature """

    @common.register_for_cmd("add", "authorization", "policy")
    def convert_policy(self, commandParseTree):
        """Convert classic Authorization policy to advanced
        Syntax:
        add authorization policy <policy name> <classic rule> <action>
        to
        add authorization policy <policy name> <advance rule> <action>
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        commandParseTree = Authorization.convert_pos_expr(commandParseTree, 1)
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        return [commandParseTree]

    # TODO need to integrate with priority interleaving.
    @common.register_for_bind(["User", "Group", "LB", "ContentSwitching"])
    def convert_authz_entity_bind(self, commandParseTree, policy_name,
                                  priority_arg, goto_arg):
        """
        Handles binding of authorization policy to AAA user and group.
        Arguments:
            commandParseTree - bind command parse tree.
            priority_arg - Indicates whether priority argument is
                           keyword or positional. It will be either
                           positional index or keyword name.
            goto_arg - Indicates whether gotoPriorityExpression
                       argument is keyword or positional argument.
                       It will be either positional index or keyword name.
        Returns converted list of parse trees.
        """
        policy_type = self.__class__.__name__
        return self.convert_entity_policy_bind(
            commandParseTree, commandParseTree,
            policy_name, policy_type, priority_arg, goto_arg)


@common.register_class_methods
class TMSession(ConvertConfig):
    """ Handle TM feature """

    # classic built-in policy and its corresponding advanced built-in policy.
    built_in_policies = {
        "SETTMSESSPARAMS_POL": "SETTMSESSPARAMS_ADV_POL"
    }

    def __init__(self):
        """
        Adds the module to the list to skip the global
        override during the priority analysis.
        """
        common.PoliciesAndBinds.add_to_skip_global_override(
            self.__class__.__name__.lower())

    @common.register_for_init_call
    def store_builtin_tmsession_policy(self):
        """
        Creates and stores Policy object for built-in TM session policy.
        """
        self.store_builtin_policies()

    @common.register_for_cmd("add", "tm", "sessionPolicy")
    def convert_policy(self, commandParseTree):
        """Convert classic TM session policy to advanced
        Syntax:
        add tm sessionPolicy <policy name> <classic rule> <action>
        to
        add tm sessionPolicy <policy name> <advance rule> <action>
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        commandParseTree = TMSession.convert_pos_expr(commandParseTree, 1)
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        return [commandParseTree]

    # override
    flow_type_direction_default = None
    bind_default_goto = "NEXT"

    @common.register_for_bind(["User", "Group", "Authentication"])
    def convert_tmsession_entity_bind(self, commandParseTree, policy_name,
                                      priority_arg, goto_arg):
        """
        Handles binding of tmsession policy to AAA user, AAA group
        and Authentication vserver.
        Arguments:
            commandParseTree - bind command parse tree.
            priority_arg - Indicates whether priority argument is
                           keyword or positional. It will be either
                           positional index or keyword name.
            goto_arg - Indicates whether gotoPriorityExpression
                       argument is keyword or positional argument.
                       It will be either positional index or keyword name.
        Returns converted list of parse trees.
        """
        policy_type = self.__class__.__name__
        # check for classic built-in policy.
        # TM session policy can be bound to aaa user, aaa group and
        # Authentication vserver.In all these bind commands, keyword used
        # for policy is "policy"
        if policy_name in self.built_in_policies:
            self.update_tree_arg(commandParseTree, "policy",
                                 self.built_in_policies[policy_name])
        return self.convert_entity_policy_bind(
            commandParseTree, commandParseTree,
            policy_name, policy_type, priority_arg, goto_arg)

    @common.register_for_cmd("bind", "tm", "global")
    def convert_tm_global(self, commandParseTree):
        """
        Handles TM global bind command.
        bind tm global [-policyName <string>
        [-priority <positive_integer>] [-gotoPriorityExpression
        <expression>]]
        """
        policy_name = commandParseTree.keyword_value("policyName")[0].value
        # TM global can bind TM sesssion policies
        # and TM traffic policies. Only TM session
        # policies have to be handled.
        if (common.pols_binds.get_policy(policy_name).module
                != self.__class__.__name__):
            return [commandParseTree]
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"
        module = self.__class__.__name__
        # check for classic built-in policy
        if policy_name in self.built_in_policies:
            self.update_tree_arg(commandParseTree, "policyName",
                                 self.built_in_policies[policy_name])
        return self.convert_global_bind(commandParseTree,
                                        commandParseTree, policy_name, module,
                                        priority_arg, goto_arg)


@common.register_class_methods
class TunnelTraffic(ConvertConfig):
    """ Handle Tunnel Traffic feature """

    flow_type_direction_default = None

    @common.register_for_cmd("add", "tunnel", "trafficPolicy")
    def convert_policy(self, commandParseTree):
        """Convert classic Tunnel traffic policy to advanced
        Syntax:
        add tunnel trafficPolicy <policy name> <classic rule> <action>
        to
        add tunnel trafficPolicy <policy name> <advance rule> <action>
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        commandParseTree = TunnelTraffic.convert_pos_expr(commandParseTree, 1)
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        return [commandParseTree]

    @common.register_for_cmd("bind", "tunnel", "global")
    def convert_tunnel_global(self, commandParseTree):
        """
        Handles tunnel global bind command.
        Syntax:
            bind tunnel global (<policyName> [-priority <positive_integer>])
            -state(ENABLED | DISABLED) [-gotoPriorityExpression <expression>]
        """
        if (commandParseTree.keyword_exists("state") and
                commandParseTree.keyword_value("state")[0].value.lower()
                == "disabled"):
            logging.warning("Following bind command is commented out because"
                            " state is disabled. If command is required"
                            " please take a backup because comments will"
                            " not be saved in ns.conf after triggering"
                            " 'save ns config': {}"
                            "".format(str(commandParseTree).strip()))
            return ['#' + str(commandParseTree)]

        # Classic built-in policy bindings should be disabled
        # and the corresponding advanced built-in policy bindings should
        # be added.
        built_in_policies = {
            "ns_tunnel_nocmp": "ns_adv_tunnel_nocmp",
            "ns_tunnel_cmpall_gzip": "ns_adv_tunnel_cmpall_gzip",
            "ns_tunnel_mimetext": "ns_adv_tunnel_mimetext",
            "ns_tunnel_msdocs": "ns_adv_tunnel_msdocs"
        }
        policy_node = commandParseTree.positional_value(0)
        policy_name = policy_node.value
        disabled_bind_list = []
        if policy_name in built_in_policies:
            disabled_classic_built_in_bind = copy.deepcopy(commandParseTree)
            # Add -state DISABLED keyword to classic
            # built-in policy bind command.
            self.update_tree_arg(disabled_classic_built_in_bind,
                                 "state", "DISABLED")
            disabled_bind_list = [disabled_classic_built_in_bind]
            disabled_classic_built_in_bind.set_upgraded()
            # Advanced built-in policy binding.
            policy_name = built_in_policies[policy_name]
            policy_node.set_value(policy_name)
            # Since built-in policy add commands are not saved
            # in ns.conf, function registered for add commands will
            # not be called for built-in policies where policy object
            # is stored.
            # Policy object should be stored here for built-in policies.
            pol_obj = common.Policy(policy_name, self.__class__.__name__,
                                    "classic")
            common.pols_binds.store_policy(pol_obj)
            # Remove the devno so that multiple lines
            # don't have the same devno.
            if commandParseTree.keyword_exists('devno'):
                commandParseTree.remove_keyword('devno')
            commandParseTree.set_upgraded()

        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"
        module = self.__class__.__name__
        return disabled_bind_list + self.convert_global_bind(
                                        commandParseTree,
                                        commandParseTree, policy_name,
                                        module, priority_arg, goto_arg)

# TODO Some of the Client Security Expressions do not have equivalent Advanced
# expressions. This may lead to some policies being converted and some not,
# which in overall will lead to invalid config. To avoid this issue,
# disabling the Classic VPNTraffic policy and its bindings conversion
# for now.

# TODO The Advanced VPNTraffic policies can have Q and S prefixes and
# SYS.EVAL_CLASSIC_EXPR expression which needs to be converted.
# Registering the VPNTraffic policy to convert_advanced_expr in AdvExpression
# class to support Advance expression conversion. While enabling back the Classic
# VPNTraffic policy conversion, remove the entry from convert_advanced_expr.

# TODO VPN class handles bindings of VPNTraffic policies. While enabling the
# VPNTraffic policy conversion, enable VPN class as well.
#@common.register_class_methods
class VPNTraffic(ConvertConfig):
    """ Handle VPN Traffic feature """

    # override
    flow_type_direction_default = None

    def __init__(self):
        """
        Adds the module to the list to skip the global
        override during the priority analysis.
        """
        common.PoliciesAndBinds.add_to_skip_global_override(
            self.__class__.__name__.lower())

    @common.register_for_cmd("add", "vpn", "trafficPolicy")
    def convert_policy(self, commandParseTree):
        """Convert classic VPN traffic policy to advanced
        Syntax:
        add vpn trafficPolicy <policy name> <classic rule> <action>
        to
        add vpn trafficPolicy <policy name> <advance rule> <action>
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        commandParseTree = VPNTraffic.convert_pos_expr(commandParseTree, 1)
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        return [commandParseTree]

    # TODO need to integrate with priority interleaving.
    @common.register_for_bind(["User", "Group", "VPN"])
    def convert_vpntraffic_entity_bind(self, commandParseTree, policy_name,
                                       priority_arg, goto_arg):
        """
        Handles binding of tmsession policy to AAA user, AAA group
        and VPN vserver.
        Arguments:
            commandParseTree - bind command parse tree.
            priority_arg - Indicates whether priority argument is
                           keyword or positional. It will be either
                           positional index or keyword name.
            goto_arg - Indicates whether gotoPriorityExpression
                       argument is keyword or positional argument.
                       It will be either positional index or keyword name.
        Returns converted list of parse trees.
        """
        policy_type = self.__class__.__name__
        return self.convert_entity_policy_bind(
            commandParseTree, commandParseTree,
            policy_name, policy_type, priority_arg, goto_arg)

# TODO VPN class is used to handle VPN global and VPN vserver bindings
# for VPNTraffic policies. Since the VPNTraffic policy conversion is disabled
# for now, disabling the binding conversion as well. Enable this back while enabling
# VPNTraffic policy conversion.
#@common.register_class_methods
class VPN(ConvertConfig):
    """
    Handles VPN global and VPN vserver
    bind command which can bind the
    following policies:
    vpn clientlessAccessPolicy,
    vpn sessionPolicy,
    vpn trafficPolicy
    We have to deal with only vpn sessionPolicies
    and vpn trafficPolicies.
    """

    # override
    flow_type_direction_default = None

    # TODO Create a new class VPNSession, Handle VPN session
    # policy conversion in VPNSession class and handle
    # VPN session policy bindings to VPN global in
    # the below method.
    @common.register_for_cmd("bind", "vpn", "global")
    def convert_vpn_global(self, commandParseTree):
        """
        Handles VPN global bind command.
        bind vpn global [-policyName <string> [-priority
        <positive_integer>][-gotoPriorityExpression <expression>]]
        """
        if not commandParseTree.keyword_exists('policyName'):
            return [commandParseTree]
        policy_name = commandParseTree.keyword_value("policyName")[0].value
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"
        if common.pols_binds.get_policy(policy_name).module == "VPNTraffic":
            module = "VPNTraffic"
            return self.convert_global_bind(commandParseTree,
                                            commandParseTree, policy_name,
                                            module, priority_arg, goto_arg)
        else:
            return [commandParseTree]

    @common.register_for_cmd("bind", "vpn", "vserver")
    def convert_vpn_vserver_bind(self, commandParseTree):
        """
        Handles VPN vserver bind command conversion.
        bind vpn vserver <name> [-policy <string> [-priority
        <positive_integer>] [-gotoPriorityExpression <expression>]
        """
        if not commandParseTree.keyword_exists('policy'):
            return [commandParseTree]

        policy_name = commandParseTree.keyword_value("policy")[0].value
        policy_type = common.pols_binds.get_policy(policy_name).module
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"

        """
        Calls the method that is registered for the particular
        policy type that is bound to vserver. Returns converted_list.
        If the policy module is not registered for binding,
        then returns the original parse tree.
        """
        key = "VPN"
        if key in common.bind_table:
            if policy_type in common.bind_table[key]:
                m = common.bind_table[key][policy_type]
                return m.method(
                    m.obj, commandParseTree, policy_name, priority_arg,
                    goto_arg)
        return [commandParseTree]


@common.register_class_methods
class APPFw(ConvertConfig):
    """ Handle APPFw feature """

    @common.register_for_cmd("add", "appfw", "policy")
    def convert_policy(self, commandParseTree):
        """Convert classic AppFw policy to advanced
        Syntax:
        add appfw policy <policy name> <classic rule> <action>
        to
        add appfw policy <policy name> <advance rule> <action>
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        commandParseTree = APPFw.convert_pos_expr(commandParseTree, 1)
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        return [commandParseTree]

    @common.register_for_cmd("bind", "appfw", "global")
    def convert_appfw_global_bind(self, commandParseTree):
        """
        Handles appfw global bindinds.
        Syntax:
            bind appfw global <policyName> <priority>
            [<gotoPriorityExpression>]
            [-state ( ENABLED | DISABLED )]
        """

        # Remove bind command when state is disabled.
        if (commandParseTree.keyword_exists("state") and
                commandParseTree.keyword_value("state")[0].value.lower()
                == "disabled"):
            logging.warning("Following bind command is commented out because"
                            " state is disabled. If command is required"
                            " please take a backup because comments will"
                            " not be saved in ns.conf after triggering"
                            " 'save ns config': {}"
                            "".format(str(commandParseTree).strip()))
            return ['#' + str(commandParseTree)]

        priority_arg = 1
        goto_arg = 2
        module = self.__class__.__name__
        policy_name = commandParseTree.positional_value(0).value
        return self.convert_global_bind(commandParseTree,
                                        commandParseTree, policy_name, module,
                                        priority_arg, goto_arg)

    @common.register_for_bind(["LB"])
    def convert_appfw_vserver_bind(self, commandParseTree, policy_name,
                                   priority_arg, goto_arg):
        """
        Handles binding of appfw policy to LB vserver.
        Arguments:
            commandParseTree - bind command parse tree.
            priority_arg - Indicates whether priority argument is
                           keyword or positional. It will be either
                           positional index or keyword name.
            goto_arg - Indicates whether gotoPriorityExpression
                       argument is keyword or positional argument.
                       It will be either positional index or keyword name.
        Returns converted list of parse trees.
        """
        policy_type = self.__class__.__name__
        return self.convert_entity_policy_bind(commandParseTree,
                                               commandParseTree, policy_name,
                                               policy_type, priority_arg,
                                               goto_arg)


@common.register_class_methods
class Syslog(ConvertConfig):
    """ Handle Nslog feature """

    # TODO Classic Syslog policy conversion is disabled for now. The Advanced
    # Syslog policies can have Q and S prefixes and SYS.EVAL_CLASSIC_EXPR expression
    # which needs to be converted. Registering the Syslog policy to convert_advanced_expr
    # in AdvExpression class to support Advance expression conversion.
    # While enabling back the Classic Syslog policy conversion, remove the
    # entry from convert_advanced_expr.

    # TODO uncomment this when the bind command conversion is supported.
    # @common.register_for_cmd("add", "audit", "syslogPolicy")
    def convert_policy(self, commandParseTree):
        """Convert classic Syslog policy to advanced
        Syntax:
        add audit syslogPolicy <policy name> <classic rule> <action>
        to
        add audit syslogPolicy <policy name> <advance rule> <action>
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        commandParseTree = Syslog.convert_pos_expr(commandParseTree, 1)
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        return [commandParseTree]


@common.register_class_methods
class Nslog(ConvertConfig):
    """ Handle Nslog feature """

    # TODO Classic Nslog policy conversion is disabled for now. The Advanced
    # Nslog policies can have Q and S prefixes and SYS.EVAL_CLASSIC_EXPR expression
    # which needs to be converted. Registering the Nslog policy to convert_advanced_expr
    # in AdvExpression class to support Advance expression conversion.
    # While enabling back the Classic Nslog policy conversion, remove the
    # entry from convert_advanced_expr.

    # TODO uncomment this when the bind command conversion is supported.
    # @common.register_for_cmd("add", "audit", "nslogPolicy")
    def convert_policy(self, commandParseTree):
        """Convert classic Nslog policy to advanced
        Syntax:
        add audit nslogPolicy <policy name> <classic rule> <action>
        to
        add audit nslogPolicy <policy name> <advance rule> <action>
        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        commandParseTree = Nslog.convert_pos_expr(commandParseTree, 1)
        pol_obj.policy_type = ("classic"
                               if commandParseTree.upgraded else "advanced")
        return [commandParseTree]


@common.register_class_methods
class Patset(ConvertConfig):
    """ Patset entity """

    @common.register_for_cmd("add", "policy", "patset")
    def register_name(self, commandParseTree):
        Patset.register_policy_entity_name(commandParseTree)
        return [commandParseTree]


@common.register_class_methods
class Dataset(ConvertConfig):
    """ Dataset entity """

    @common.register_for_cmd("add", "policy", "dataset")
    def register_name(self, commandParseTree):
        Dataset.register_policy_entity_name(commandParseTree)
        return [commandParseTree]


@common.register_class_methods
class HTTP_CALLOUT(ConvertConfig):
    """ HTTP callout entity """

    @common.register_for_cmd("add", "policy", "httpCallout")
    def register_name(self, commandParseTree):
        callout_name = commandParseTree.positional_value(0).value
        lower_callout_name = callout_name.lower()
        if (lower_callout_name in classic_entities_names):
            """
                This will be true only if the classic named expression has
                the same name as the callout entity name.
            """
            logging.error(("HTTP callout name {} is conflicting with"
                           " named expression entity name, please resolve"
                           " the conflict.").format(callout_name))
        else:
            HTTP_CALLOUT.register_policy_entity_name(commandParseTree)
        commandParseTree = HTTP_CALLOUT.convert_adv_expr_list(
                            commandParseTree, ["hostExpr", "urlStemExpr", "headers",
                            "parameters", "bodyExpr", "fullReqExpr", "resultExpr"])
        return [commandParseTree]


@common.register_class_methods
class StringMap(ConvertConfig):
    """ String map entity """

    @common.register_for_cmd("add", "policy", "stringmap")
    def register_name(self, commandParseTree):
        StringMap.register_policy_entity_name(commandParseTree)
        return [commandParseTree]


@common.register_class_methods
class NSVariable(ConvertConfig):
    """ NS Variable entity """

    @common.register_for_cmd("add", "ns", "variable")
    def register_name(self, commandParseTree):
        NSVariable.register_policy_entity_name(commandParseTree)
        return [commandParseTree]


@common.register_class_methods
class EncryptionKey(ConvertConfig):
    """ Encryption key entity """

    @common.register_for_cmd("add", "ns", "encryptionKey")
    def register_name(self, commandParseTree):
        EncryptionKey.register_policy_entity_name(commandParseTree)
        return [commandParseTree]


@common.register_class_methods
class HMACKey(ConvertConfig):
    """ HMAC key entity """

    @common.register_for_cmd("add", "ns", "hmacKey")
    def register_name(self, commandParseTree):
        HMACKey.register_policy_entity_name(commandParseTree)
        return [commandParseTree]


@common.register_class_methods
class NamedExpression(ConvertConfig):
    """ Handle Named expression feature """

    csec_expr_list = OrderedDict()

    # Built-in classic named expression names and there
    # corresponding built-in advanced named expression names.
    built_in_named_expr = {
        "ns_true": "TRUE",
        "ns_false": "FALSE",
        "ns_non_get": "ns_non_get_adv",
        "ns_cachecontrol_nostore": "ns_cachecontrol_nostore_adv",
        "ns_cachecontrol_nocache": "ns_cachecontrol_nocache_adv",
        "ns_header_pragma": "ns_header_pragma_adv",
        "ns_header_cookie": "ns_header_cookie_adv",
        "ns_ext_cgi": "ns_ext_cgi_adv",
        "ns_ext_asp": "ns_ext_asp_adv",
        "ns_ext_exe": "ns_ext_exe_adv",
        "ns_ext_cfm": "ns_ext_cfm_adv",
        "ns_ext_ex": "ns_ext_ex_adv",
        "ns_ext_shtml": "ns_ext_shtml_adv",
        "ns_ext_htx": "ns_ext_htx_adv",
        "ns_url_path_cgibin": "ns_url_path_cgibin_adv",
        "ns_url_path_exec": "ns_url_path_exec_adv",
        "ns_url_path_bin": "ns_url_path_bin_adv",
        "ns_url_tokens": "ns_url_tokens_adv",
        "ns_ext_not_gif": "ns_ext_not_gif_adv",
        "ns_ext_not_jpeg": "ns_ext_not_jpeg_adv",
        "ns_cmpclient": "ns_cmpclient_adv",
        "ns_slowclient": "ns_slowclient_adv",
        "ns_content_type": "ns_content_type_advanced",
        "ns_msword": "ns_msword_advanced",
        "ns_msexcel": "ns_msexcel_advanced",
        "ns_msppt": "ns_msppt_advanced",
        "ns_css": "ns_css_adv",
        "ns_xmldata": "ns_xmldata_adv",
        "ns_mozilla_47": "ns_mozilla_47_adv",
        "ns_msie": "ns_msie_adv"
    }

    @staticmethod
    def register_built_in_named_exprs():
        """
        Register built-in classic Named expression names in
        classic_entities_names and built-in advanced Named expression names
        in policy_entities_names.
        """
        for classic_exp_name in NamedExpression.built_in_named_expr:
            classic_entities_names.add(classic_exp_name)
            policy_entities_names.add(NamedExpression.built_in_named_expr[
                                      classic_exp_name].lower())

    @common.register_for_cmd("add", "policy", "expression")
    def convert_policy(self, commandParseTree):
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
             "s",
             "q",
             "re",
             "xp",
             "ce"
             ])

        expr_name = commandParseTree.positional_value(0).value
        expr_rule = commandParseTree.positional_value(1).value
        lower_expr_name = expr_name.lower()
        named_expr[lower_expr_name] = expr_rule
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
            NamedExpression.csec_expr_list[lower_expr_name] = {}
            NamedExpression.csec_expr_list[lower_expr_name]["tree"] = commandParseTree
            NamedExpression.csec_expr_list[lower_expr_name]["error_displayed"] = False
            NamedExpression.register_classic_entity_name(commandParseTree)
            return [commandParseTree]

        csec_expr_info = has_client_security_expressions(expr_rule)
        if csec_expr_info[0]:
            NamedExpression.csec_expr_list[lower_expr_name] = {}
            NamedExpression.csec_expr_list[lower_expr_name]["tree"] = commandParseTree
            NamedExpression.csec_expr_list[lower_expr_name]["error_displayed"] = False
            NamedExpression.register_classic_entity_name(commandParseTree)
            return [commandParseTree]

        original_tree = copy.deepcopy(commandParseTree)
        """Convert classic named expression to advanced
        Syntax:
        add policy expression <expression name> <classic expression>
        to
        add policy expression <expression name> <advanced expression>
        """
        commandParseTree = NamedExpression \
            .convert_pos_expr(commandParseTree, 1)

        if commandParseTree.adv_upgraded:
            tree_list = [commandParseTree]
        else:
            tree_list = [original_tree]
        if commandParseTree.upgraded:
            """
                Because we are not currently converting all the commands that
                use named expressions, we can have the situation where a
                non-converted command uses a Classic named expression but a
                converted command would have used the same named expression.
                To deal with this we create an Advanced that is equivalent
                to the old Classic, give it a new name, and replace all the
                references to the old Classic in converted expressions to the
                corresponding Advanced. Because of that we need to return
                both the old Classic and corresponding Advanced named
                expressions from this routine.
            """
            name_node = commandParseTree.positional_value(0)
            name_node.set_value(get_advanced_name(name_node.value))
            # Remove the devno so that multiple lines
            # don't have the same devno.
            if commandParseTree.keyword_exists('devno'):
                commandParseTree.remove_keyword('devno')
            tree_list.append(commandParseTree)
            NamedExpression.register_policy_entity_name(commandParseTree)
            NamedExpression.register_classic_entity_name(original_tree)
        else:
            NamedExpression.register_policy_entity_name(original_tree)
        return tree_list


@common.register_class_methods
class HTTPProfile(ConvertConfig):
    """ Handle HTTP Profile """

    @common.register_for_cmd("add", "ns", "httpProfile")
    @common.register_for_cmd("set", "ns", "httpProfile")
    def convert_spdy(self, commandParseTree):
        """Convert spdy feature to HTTP2
        Syntax:
        add ns httpProfile <profile name> -spdy <V2/V3/ENABLED>
        to
        add ns httpProfile <profile name> -http2 ENABLED
        """
        if commandParseTree.keyword_exists('spdy'):
                commandParseTree.remove_keyword('spdy')
                http2_keyword = CLIKeywordParameter(CLIKeywordName("http2"))
                http2_keyword.add_value('ENABLED')
                commandParseTree.add_keyword(http2_keyword)
        commandParseTree = HTTPProfile \
			.convert_adv_expr_list(commandParseTree, ["clientIpHdrExpr"])
        return [commandParseTree]


@common.register_class_methods
class ContentSwitching(ConvertConfig):
    """ Handle Content Switching feature """

    # override
    bind_default_goto = None

    def __init__(self):
        """
        _policy_bind_info - Contains information about classic policies
                            without actions and there bind commands.
                            key - policy name
                            value - dictionary with the following keys:
                                    "policy_tree" - Policy tree without action
                                    "bind_trees" - List of bind trees where
                                                   the corresponding policy is
                                                   bound.
        _cs_vserver_info_ci - List of the CS vserver name for which
                              caseSensitive parameter is set to OFF.
        _policy_url_info - Contains information about classic policies
                           using url parameter.
                           key - policy name
                           value - converted advanced expression for
                                   case insensitive search, which will
                                   be used if the policy is bound to
                                   any CS vserver for which caseSensitive
                                   parameter is set to OFF.
        """
        self._policy_bind_info = OrderedDict()
        self._cs_vserver_info_ci = []
        self._policy_url_info = OrderedDict()

    @common.register_for_cmd("add", "cs", "vserver")
    def convert_cs_vserver(self, commandParseTree):
        """
        Get vserver protocol to help in filter bind conversion
        cs_protocol - cs vserver protocol
        csv_name - cs vserver name
        vserver_protocol_dict - dict to store protocol as value to the
                 vserver name as key
        """

        if commandParseTree.keyword_exists('td'):
            cs_protocol = str(commandParseTree.keyword_value('td')[1])
        else:
            cs_protocol = commandParseTree.positional_value(1).value

        csv_name = commandParseTree.positional_value(0).value
        vserver_protocol_dict[csv_name] = cs_protocol.upper()

        # Remove caseSensitive parameter as it has no effect
        # on advanced expression.
        if commandParseTree.keyword_exists('caseSensitive'):
            commandParseTree.remove_keyword('caseSensitive')
            self._cs_vserver_info_ci.append(csv_name)

        commandParseTree = ContentSwitching.convert_adv_expr_list(
                            commandParseTree, ["Listenpolicy", "pushLabel"])
        return [commandParseTree]

    @common.register_for_cmd("add", "cs", "policy")
    def convert_policy(self, commandParseTree):
        """Convert CS policy to advanced
        Syntax:
        Conversion happens as:
        1. add cs policy <policy name> -domain <domain>
           to
           add cs policy <policy name> -rule HTTP.REQ.HOSTNAME.EQ("<domain>")

        2. add cs policy <policy name> -rule <rule>
           to
           add cs policy <policy name> -rule <rule>

        3. add cs policy <policy name> -rule <rule> -domain <domain>
           to
           add cs policy <policy name> -rule
               '<rule> && HTTP.REQ.HOSTNAME.EQ("<domain>")'

        4. add cs policy <policy name> -url <url>
           to
           add cs policy <policy name> -rule <url based expression>

        5. add cs policy <policy name> -url <url> -domain <domain>
           to
           add cs policy <policy name> -rule <url based expression
               && HTTP.REQ.HOSTNAME.EQ("<domain>")>

        """
        policy_name = commandParseTree.positional_value(0).value
        pol_obj = common.Policy(policy_name, self.__class__.__name__)
        common.pols_binds.store_policy(pol_obj)
        """ Only in advanced policy, action can be present.
        """
        if commandParseTree.keyword_exists('action'):
            pol_obj.policy_type = "advanced"
            commandParseTree = ContentSwitching.convert_adv_expr_list(
                                commandParseTree, ["rule"])
            return [commandParseTree]
        if commandParseTree.keyword_exists('rule'):
            if commandParseTree.keyword_exists('domain'):
                    rule_node = commandParseTree.keyword_value('rule')
                    rule_expr = rule_node[0].value
                    converted_expr = convert_classic_expr.convert_classic_expr(
                        rule_expr)
                    if converted_expr is None:
                        logging.error('Error in converting command : ' +
                                      str(commandParseTree).strip())
                        return [commandParseTree]
                    converted_expr = converted_expr.strip('"')
                    domain_name = commandParseTree.keyword_value('domain')[0] \
                        .value
                    domain_rule = 'HTTP.REQ.HOSTNAME.EQ(\\"' + \
                        domain_name + '\\")'
                    commandParseTree.remove_keyword('domain')
                    complete_expr = '"(' + converted_expr + ') && ' + \
                        domain_rule + '"'
                    rule_node[0].set_value(complete_expr, True)
                    commandParseTree.set_upgraded()
            else:
                commandParseTree = ContentSwitching \
                    .convert_keyword_expr(commandParseTree, 'rule')
        elif commandParseTree.keyword_exists('url'):
            domain_rule = None
            converted_url_expr = None
            prefix = None
            prefix_val = None
            suffix = None
            converted_url_expr_ci = None
            start_expr = 'HTTP.REQ.URL.PATH.'
            start_expr_ci = 'HTTP.REQ.URL.PATH.SET_TEXT_MODE(IGNORECASE).'
            append_start_expr = True
            url_expr = commandParseTree.keyword_value('url')[0].value
            last_url_expr = url_expr.rsplit('/', 1)
            converted_url_expr = 'EQ("' + \
                url_expr + '")'
            if ((last_url_expr[1] == '') or
                (('.' not in last_url_expr[1]) and
                ('*' not in last_url_expr[1]))):
                converted_url_expr = 'EQ(("' + \
                    url_expr + '." + HTTP.REQ.URL.SUFFIX).' + \
                    'STRIP_END_CHARS("."))'
            elif url_expr.endswith('.'):
                converted_url_expr = 'EQ("' + \
                    url_expr + '")'
            elif url_expr.endswith('*'):
                if (url_expr[-3:] == '*.*'):
                    converted_url_expr = 'STARTSWITH("' + \
                        url_expr[0: -3] + '")'
                elif (url_expr[-2:] == '.*'):
                    converted_url_expr = 'EQ(("' + \
                        url_expr[0:-1] + \
                        '" + HTTP.REQ.URL.SUFFIX).STRIP_END_CHARS("."))'                       
                elif (url_expr == '/*'):
                    converted_url_expr = 'true'
                    append_start_expr = False
                else:
                    converted_url_expr =  'STARTSWITH("' + \
                        url_expr[0:-1] + '")'
            else:
                prefix_suffix = last_url_expr[1].rsplit('.', 1)
                if len(prefix_suffix) is 1:
                    converted_url_expr = 'EQ(("' + \
                        url_expr + \
                        '." + HTTP.REQ.URL.SUFFIX).STRIP_END_CHARS("."))'                       
                else:
                    """ Suffix is present in URL."""
                    prefix_suffix = url_expr.rsplit('.', 1)
                    prefix = prefix_suffix[0]
                    suffix = prefix_suffix[1]
                    if prefix == '/':
                        converted_url_expr = 'EQ(("/."' + \
                            ' + HTTP.REQ.URL.SUFFIX).STRIP_END_CHARS(' + \
                            '"."))'
                    elif prefix.endswith('*'):
                        converted_url_expr = '(HTTP.REQ.URL.PATH.STARTSWITH' + \
                            '("' + prefix[0:-1] + \
                            '") && HTTP.REQ.URL.SUFFIX.EQ("' + \
                            suffix + '"))'
                        converted_url_expr_ci = '(HTTP.REQ.URL.PATH.' + \
                            'SET_TEXT_MODE(IGNORECASE).STARTSWITH' + \
                            '("' + prefix[0:-1] + \
                            '") && HTTP.REQ.URL.SUFFIX.EQ("' + \
                            suffix + '"))'
                        append_start_expr = False

            if append_start_expr:
                converted_url_expr = start_expr +  converted_url_expr
                converted_url_expr_ci = start_expr_ci +  converted_url_expr

            if commandParseTree.keyword_exists('domain'):
                domain_name = commandParseTree.keyword_value('domain')[0] \
                    .value
                domain_rule = 'HTTP.REQ.HOSTNAME.EQ("' + domain_name + '")'
                commandParseTree.remove_keyword('domain')

            if (domain_rule):
                converted_url_expr = converted_url_expr + ' && ' + domain_rule

            commandParseTree.remove_keyword('url')
            rule_keyword = CLIKeywordParameter(CLIKeywordName('rule'))
            rule_keyword.add_value(converted_url_expr)
            commandParseTree.add_keyword(rule_keyword)
            if converted_url_expr_ci is not None:
                self._policy_url_info[policy_name] = converted_url_expr_ci
        elif commandParseTree.keyword_exists('domain'):
            domain_name = commandParseTree.keyword_value('domain')[0].value
            domain_rule = 'HTTP.REQ.HOSTNAME.EQ("' + domain_name + '")'
            commandParseTree.remove_keyword('domain')
            rule_keyword = CLIKeywordParameter(CLIKeywordName("rule"))
            rule_keyword.add_value(domain_rule)
            commandParseTree.add_keyword(rule_keyword)

        if commandParseTree.upgraded:
            pol_obj.policy_type = "classic"
            # Saving policies for resolving multiple bind points for
            # CS policies without action issue.
            self._policy_bind_info[policy_name] = {}
            self._policy_bind_info[policy_name]["policy_tree"] = \
                commandParseTree
            return []
        else:
            pol_obj.policy_type = "advanced"
            return [commandParseTree]

    @common.register_for_cmd("bind", "cs", "vserver")
    def convert_cs_bind_command(self, commandParseTree):
        """
        Handles CS vserver bind command.
        bind cs vserver <name> -policyName <string>
        -priority <integer> [-gotoPriorityExpression <expression>]
        """
        if not commandParseTree.keyword_exists('policyName'):
            return [commandParseTree]

        # Get the policy name
        policy_name = commandParseTree.keyword_value('policyName')[0].value
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"

        class_name = self.__class__.__name__
        policy_type = common.pols_binds.get_policy(policy_name).module
        if policy_type == class_name:
            if policy_name in self._policy_bind_info:
                # Saving bind commands for resolving multiple bind points for
                # CS policies without action issue.
                if "bind_trees" not in self._policy_bind_info[policy_name]:
                    self._policy_bind_info[policy_name]["bind_trees"] = []
                self._policy_bind_info[policy_name]["bind_trees"].append(
                                                        commandParseTree)
                return []
            else:
                return self.convert_entity_policy_bind(
                    commandParseTree, commandParseTree,
                    policy_name, policy_type, priority_arg, goto_arg)

        """
        Calls the method that is registered for the particular
        policy type that is bound to CS. Returns converted_list.
        If the policy module is not registered for binding,
        then returns the original parse tree.
        """
        key = "ContentSwitching"
        if key in common.bind_table:
            if policy_type in common.bind_table[key]:
                m = common.bind_table[key][policy_type]
                return m.method(m.obj, commandParseTree, policy_name,
                                priority_arg, goto_arg)
        return [commandParseTree]

    @common.register_for_bind(["CacheRedirection"])
    def convert_cs_policy_entity_bind(
            self, commandParseTree, policy_name, priority_arg, goto_arg):
        """
        Handles CS policy binding to CR vserver.
        Arguments:
            commandParseTree - bind command parse tree.
            priority_arg - Indicates whether priority argument is
                           keyword or positional. It will be either
                           positional index or keyword name.
            goto_arg - Indicates whether gotoPriorityExpression
                       argument is keyword or positional argument.
                       It will be either positional index or keyword name.
        Returns converted list of parse trees.
        """
        policy_type = self.__class__.__name__
        if policy_name in self._policy_bind_info:
            # Saving bind commands for resolving multiple bind points for
            # CS policies without action issue.
            if "bind_trees" not in self._policy_bind_info[policy_name]:
                self._policy_bind_info[policy_name]["bind_trees"] = []
            self._policy_bind_info[policy_name]["bind_trees"].append(
                                                    commandParseTree)
            return []
        else:
            return self.convert_entity_policy_bind(
                commandParseTree, commandParseTree,
                policy_name, policy_type, priority_arg, goto_arg)

    @common.register_for_final_call
    def get_converted_cmds(self):
        """
        Classic CS policies do not support CS action. But in advanced policies
        there is limitation that multiple bind points are not allowed for
        CS policies without action. This will lead to issue during the
        conversion if any classic CS policy is bound to multiple bind points.
        To avoid this issue following steps are followed for each bind command:
        1. Get policy name and vserver name from bind command.
        2. New action is created with name "nspepi_adv_cs_act_<vserver_name>"
        3. New policy is created with name
           "nspepi_adv_<policy_name>_<vserver_name>" and
           set action keyword to "nspepi_adv_cs_act_<vserver_name>"
        4. Remove targetLBVserver from bind command and update the policy name
           to newly created policy name.
        5. If same policy is bound to different vservers, multiple policies
           are created.
        CS policies can be bound to CS vserver and CR vserver.
        Return list of newly added CS actions and policies.
        """
        newly_added_policy_names = []
        newly_added_action_names = []
        pol_list = []
        act_list = []
        overlength_action_names = {}
        overlength_policy_names = {}
        overlength_action_counter = 0
        overlength_policy_counter = 0
        for policy_name in self._policy_bind_info:
            policy_tree = self._policy_bind_info[policy_name]["policy_tree"]
            if "bind_trees" not in self._policy_bind_info[policy_name]:
                # when policy is not used in any bind command.
                pol_list.append(policy_tree)
                continue
            for index in range(len(self._policy_bind_info[policy_name][
                                                    "bind_trees"])):
                vserver_name = ""
                cs_vserver_name = ""
                bind_tree = self._policy_bind_info[policy_name][
                    "bind_trees"][index]
                if ((' '.join(bind_tree.get_command_type())).lower() ==
                        "bind cs vserver"):
                    vserver_name = bind_tree.keyword_value(
                        "targetLBVserver")[0].value
                    cs_vserver_name = bind_tree.positional_value(0).value
                elif ((' '.join(bind_tree.get_command_type())).lower() ==
                        "bind cr vserver"):
                    vserver_name = bind_tree.keyword_value(
                        "policyName")[1].value
                new_policy_name = "nspepi_adv_" + policy_name + '_' + \
                    vserver_name
                set_ci_rule = False
                # If CS vserver is configured with caseSensitive
                # parameter set to OFF and policy is configured
                # with URL parameter, then add '_ci' suffix in the
                # new policy name and rule of that policy should
                # do case-insensitive search.
                if ((cs_vserver_name in self._cs_vserver_info_ci) and
                    (policy_name in self._policy_url_info)):
                    new_policy_name += '_ci'
                    set_ci_rule = True
                truncated_pol_name = new_policy_name
                action_name = "nspepi_adv_cs_act_" + vserver_name
                truncated_act_name = action_name
                if new_policy_name not in newly_added_policy_names:
                    if action_name not in newly_added_action_names:
                        # Create new action
                        action_tree = CLICommand("add", "cs", "action")
                        # Check action name length. Max allowed length is 127
                        if len(action_name) > 127:
                            truncated_act_name, overlength_action_counter = \
                                self.truncate_name(action_name,
                                                   overlength_action_names,
                                                   overlength_action_counter)
                        pos = CLIPositionalParameter(truncated_act_name)
                        action_tree.add_positional(pos)
                        vserver_key = CLIKeywordParameter(CLIKeywordName(
                            "targetLBVserver"))
                        vserver_key.add_value(vserver_name)
                        action_tree.add_keyword(vserver_key)
                        act_list.append(action_tree)
                        newly_added_action_names.append(action_name)
                    else:
                        # when action is already added.
                        # Get truncated name if truncated.
                        if action_name in overlength_action_names:
                            truncated_act_name = overlength_action_names[
                                action_name]
                    # Create new policy with [policy_name]_[vserver_name] as
                    # as name and bind to newly created action
                    # cs_act_[vserver_name]
                    new_policy = copy.deepcopy(policy_tree)
                    # Max length of policy name allowed is 127.
                    truncated_pol_name = new_policy_name
                    if len(new_policy_name) > 127:
                        truncated_pol_name, overlength_policy_counter = \
                            self.truncate_name(new_policy_name,
                                               overlength_policy_names,
                                               overlength_policy_counter)
                    self.update_tree_arg(new_policy, 0, truncated_pol_name)
                    if set_ci_rule:
                        rule_node = new_policy.keyword_value('rule')
                        rule_node[0].set_value(self._policy_url_info[policy_name], True)
                    action_key = CLIKeywordParameter(CLIKeywordName("action"))
                    action_key.add_value(truncated_act_name)
                    new_policy.add_keyword(action_key)
                    # Remove the devno so that multiple lines
                    # don't have the same devno.
                    if new_policy.keyword_exists('devno'):
                        new_policy.remove_keyword('devno')
                    newly_added_policy_names.append(new_policy_name)
                    pol_list.append(new_policy)
                else:
                    # When policy is already added.
                    # Get truncated policy name if truncated.
                    if new_policy_name in overlength_policy_names:
                        truncated_pol_name = overlength_policy_names[
                            new_policy_name]
                # Remove targetLBVserver from bind command and update policy
                # name to newly added policy name.
                priority_arg = "priority"
                goto_arg = "gotoPriorityExpression"
                policy_type = self.__class__.__name__
                self.update_tree_arg(bind_tree, "policyName",
                                     truncated_pol_name)
                if ((' '.join(bind_tree.get_command_type())).lower() ==
                        "bind cs vserver"):
                    bind_tree.remove_keyword("targetLBVserver")
                elif ((' '.join(bind_tree.get_command_type())).lower() ==
                        "bind cr vserver"):
                    # In bind cr vserver command, vserver name exists in
                    # following way:
                    # bind cr vserver <vserver> -policyName <policy name>
                    #                                       <vserver name>
                    bind_tree.remove_keyword_value("policyName", 1)
                self.convert_entity_policy_bind(
                    bind_tree, bind_tree, policy_name,
                    policy_type, priority_arg, goto_arg)
        return act_list + pol_list

    def truncate_name(self, name, name_mapping, counter):
        """
        Truncates name shorter than 127 and adds a counter at the end.
        name - name that should be truncated.
        name_mapping - dictionary which saves name and its truncated name.
                       key - name
                       value - truncated name
        counter - counter to be appended at the end of truncated name.
        """
        counter += 1
        # Reserving 1 for '_' + 6 for counter.
        truncated_name = name[0: 120]
        truncated_name += "_" + str(counter)
        name_mapping[name] = truncated_name
        return truncated_name, counter


@common.register_class_methods
class AAA(ConvertConfig):

    @common.register_for_cmd("add", "aaa", "group")
    def convert_add_group(self, tree):
        """
        Process: add aaa group <groupName> [-weight <positive_integer>]
        and store weight for each group.

        Args:
            tree: Command parse tree for add aaa group command

        Returns:
            tree: Processed command parse tree for add aaa group command
        """
        groupname = common.get_cmd_arg(0, tree)
        weight = common.get_cmd_arg("weight", tree)
        weight = weight if weight else "0"
        common.pols_binds.store_group(common.Group(groupname, weight))
        return [tree]

    def user_group_bind_common(self, tree, key):
        """
        Common processing for bind aaa user and bind aaa group.
        bind aaa user <userName> [-policy <policyName>]
            [-priority <priority>] [-type <bindType>]
            [-gotoPriorityExpression <expression>] ...
        bind aaa group <groupName> [-policy <policyName>]
            [-priority <priority>] [-type <bindType>]
            [-gotoPriorityExpression <expression>] ...
        """
        policy_name = common.get_cmd_arg("policy", tree)
        if not policy_name:
            return [tree]
        policy_type = common.pols_binds.get_policy(policy_name).module
        priority_arg = "priority"
        goto_arg = "gotoPriorityExpression"

        # Calls the method that is registered for the particular
        # policy type that is bound to the user or group.
        # Returns converted_list.  If the policy module is not
        # registered for binding, then returns the original parse
        # tree.
        if key in common.bind_table:
            if policy_type in common.bind_table[key]:
                m = common.bind_table[key][policy_type]
                return m.method(m.obj, tree, policy_name, priority_arg,
                                goto_arg)
        return [tree]

    @common.register_for_cmd("bind", "aaa", "user")
    def convert_user_bind(self, tree):
        return self.user_group_bind_common(tree, "User")

    @common.register_for_cmd("bind", "aaa", "group")
    def convert_group_bind(self, tree):
        return self.user_group_bind_common(tree, "Group")

@common.register_class_methods
class AdvExpression(ConvertConfig):
    """
    Handles conversion of Q and S prefixes and SYS.EVAL_CLASSIC_EXPR expression in commands
    which allows only advanced expressions.
    """

    @common.register_for_cmd("add", "videooptimization", "detectionpolicy")
    @common.register_for_cmd("add", "videooptimization", "pacingpolicy")
    @common.register_for_cmd("add", "dns", "policy")
    @common.register_for_cmd("add", "cache", "selector")
    @common.register_for_cmd("add", "cs", "action")
    @common.register_for_cmd("add", "vpn", "clientlessAccessPolicy")
    @common.register_for_cmd("add", "authentication", "webAuthAction")
    @common.register_for_cmd("set", "authentication", "webAuthAction")
    @common.register_for_cmd("add", "tm", "trafficPolicy")
    @common.register_for_cmd("add", "authentication", "samlIdPPolicy")
    @common.register_for_cmd("add", "feo", "policy")
    @common.register_for_cmd("add", "cache", "policy")
    @common.register_for_cmd("add", "transform", "policy")
    @common.register_for_cmd("add", "appqoe", "action")
    @common.register_for_cmd("add", "appqoe", "policy")
    @common.register_for_cmd("add", "appflow", "policy")
    @common.register_for_cmd("add", "autoscale", "policy")
    @common.register_for_cmd("add", "authentication", "Policy")
    @common.register_for_cmd("add", "authentication", "loginSchemaPolicy")
    @common.register_for_cmd("add", "authentication", "loginSchema")
    @common.register_for_cmd("add", "gslb", "vserver")
    @common.register_for_cmd("add", "ns", "assignment")
    @common.register_for_cmd("add", "dns", "action64")
    @common.register_for_cmd("add", "dns", "policy64")
    @common.register_for_cmd("add", "authentication", "OAuthIdPPolicy")
    @common.register_for_cmd("add", "authentication", "samlIdPProfile")
    @common.register_for_cmd("add", "contentInspection", "policy")
    @common.register_for_cmd("add", "ica", "policy")
    @common.register_for_cmd("add", "lb", "group")
    @common.register_for_cmd("add", "audit", "messageaction")
    @common.register_for_cmd("add", "aaa", "preauthenticationpolicy")
    @common.register_for_cmd("add", "spillover", "policy")
    @common.register_for_cmd("add", "stream", "selector")
    @common.register_for_cmd("add","tm", "formSSOAction")
    @common.register_for_cmd("add", "tm", "samlSSOProfile")
    @common.register_for_cmd("add", "vpn", "sessionPolicy")
    @common.register_for_cmd("add", "vpn", "trafficAction")
    @common.register_for_cmd("add", "vpn", "vserver")
    # TODO: This entry need to be removed when Classic Syslog policy
    # conversion is enabled in Syslog class.
    @common.register_for_cmd("add", "audit", "syslogPolicy")
    # TODO: This entry need to be removed when Classic Nslog policy
    # conversion is enabled in Nslog class.
    @common.register_for_cmd("add", "audit", "nslogPolicy")
    # TODO: This entry need to be removed when Classic authorization policy
    # conversion is enabled in Authorization class.
    @common.register_for_cmd("add", "authorization", "policy")
    # TODO: This entry need to be removed when Classic VPNTraffic policy
    # conversion is enabled in VPNTraffic class.
    @common.register_for_cmd("add", "vpn", "trafficPolicy")
    def convert_advanced_expr(self, tree):
        """
        Commands which allows ONLY advanced expressions should be registered for this method.
        Handles conversion of Q and S prefixes and SYS.EVAL_CLASSIC_EXPR expression.
        Each command that will be registered to this method, should add an entry in
        command_parameters_list.
        """

        # Each command should mention the list of parameters where advanced expression
        # can be used. Only these parameters will be checked for SYS.EVAL_CLASSIC_EXPR
        # expression.
        # If its a keyword parameter, mention the keyword name.
        # If its a positional parameter, mention the position of the parameter.
        command_parameters_list = {
            "add videooptimization detectionpolicy": ["rule"],
            "add videooptimization pacingpolicy": ["rule"],
            "add dns policy": [1],
            "add cache selector": [1, 2, 3, 4, 5, 6, 7, 8],
            "add cs action": ["targetVserverExpr"],
            "add vpn clientlessaccesspolicy": [1],
            "add authentication webauthaction": ["fullReqExpr", "successRule"],
            "set authentication webauthaction": ["fullReqExpr", "successRule"],
            "add tm trafficpolicy": [1],
            "add authentication samlidppolicy": ["rule"],
            "add feo policy": [1],
            "add cache policy": ["rule"],
            "add transform policy": [1],
            "add appqoe action": ["dosTrigExpression"],
            "add appqoe policy": ["rule"],
            "add ssl policy": ["rule"],
            "add appflow policy": [1],
            "add autoscale policy": ["rule"],
            "add authentication policy": ["rule"],
            "add authentication loginschemapolicy": ["rule"],
            "add authentication loginschema": ["userExpression", "passwdExpression"],
            "add gslb vserver": ["rule"],
            "add ns assignment": ["set", "append", "add", "sub"],
            "add dns action64": ["mappedRule", "excludeRule"],
            "add dns policy64": ["rule"],
            "add authentication oauthidppolicy": ["rule"],
            "add authentication samlidpprofile": ["NameIDExpr", "acsUrlRule"],
            "add contentinspection policy": ["rule"],
            "add ica policy": ["rule"],
            "add lb group": ["rule"],
            "add audit messageaction": [2],
            "add aaa preauthenticationpolicy": [1],
            "add spillover policy": ["rule"],
            "add stream selector": [1, 2, 3, 4, 5],
            "add tm formssoaction": ["ssoSuccessRule"],
            "add tm samlssoprofile": ["relaystateRule", "NameIDExpr"],
            "add vpn sessionpolicy": [1],
            "add vpn trafficaction": ["userExpression", "passwdExpression"],
            "add vpn vserver": ["Listenpolicy"],
            # TODO: This entry need to be removed when Classic Syslog policy
            # conversion is enabled in Syslog class.
            "add audit syslogpolicy": [1],
            # TODO: This entry need to be removed when Classic Nslog policy
            # conversion is enabled in Nslog class.
            "add audit nslogpolicy": [1],
            # TODO: This entry need to be removed when Classic authorization policy
            # conversion is enabled in Authorization class.
            "add authorization policy": [1],
            # TODO: This entry need to be removed when Classic VPNTraffic policy
            # conversion is enabled in VPNTraffic class.
            "add vpn trafficpolicy": [1],
        }

        command = " ".join(tree.get_command_type()).lower()
        if command in command_parameters_list:
            tree = AdvExpression.convert_adv_expr_list(tree, command_parameters_list[command])
        return [tree]

@common.register_class_methods
class SSL(ConvertConfig):
    """ Handle SSL feature """

    @common.register_for_cmd("add", "ssl", "policy")
    def convert_policy(self, commandParseTree):
        """
        Check classic SSL policy.
        """
        original_tree = copy.deepcopy(commandParseTree)
        convertedParseTree = SSL.convert_keyword_expr(commandParseTree, 'rule')
        if convertedParseTree.upgraded:
            logging.error(("Classic SSL policy [{}] is not working from 10.1 release, "
                           "please remove the classic SSL policy configuration "
                           "from the config file").format(str(original_tree).strip()))
            return [original_tree]
        return [commandParseTree]


@common.register_class_methods
class SureConnect(ConvertConfig):
    """
    Handle SureConnect commands
    """
    @common.register_for_cmd("add", "sc", "policy")
    @common.register_for_cmd("set", "sc", "parameter")
    def convert_policy(self, commandParseTree):
        logging.error(("SureConnect feature command [{}] conversion "
                       "is not supported, please do the conversion "
                       "manually").format(str(commandParseTree).strip()))
        return [commandParseTree]


@common.register_class_methods
class PriorityQueuing(ConvertConfig):
    """
    Hanlde PriorityQueuing commands
    """
    @common.register_for_cmd("add", "pq", "policy")
    def convert_policy(self, commandParseTree):
        logging.error(("PriorityQueuing feature command [{}] conversion "
                       "is not supported, please do the conversion "
                       "manually").format(str(commandParseTree).strip()))
        return [commandParseTree]


@common.register_class_methods
class HDoSP(ConvertConfig):
    """
    Handle HTTP Denial of Service Protection commands
    """
    @common.register_for_cmd("add", "dos", "policy")
    def convert_policy(self, commandParseTree):
        logging.error(("HDoSP feature command [{}] conversion "
                       "is not supported, please do the conversion "
                       "manually").format(str(commandParseTree).strip()))
        return [commandParseTree]
