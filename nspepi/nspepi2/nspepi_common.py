#!/usr/bin/env python

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

"""
Common data for nspepi accessible from other modules.
Dependency packages: None
"""

import collections
import copy
import functools
import itertools
import logging
import sys
import os
import inspect


import nspepi_parse_tree

currentfile = os.path.abspath(inspect.getfile(inspect.currentframe()))
currentdir = os.path.dirname(currentfile)
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)


def get_nspepi_tool_path():
    """ Get the path of old nspepi tool.
    This function will check whether the tool
    exists in the current directory or the
    parent directory, and return the path
    based on that."""
    file_found = False
    filename = 'nspepi_helper'
    for path in [currentdir, parentdir]:
        candidate = os.path.join(path, filename)
        if os.path.isfile(candidate):
            file_found = True
            break
    if file_found:
        return os.path.abspath(candidate)
    else:
        return None


CMD_MOD_ERR_MSG = (" Advanced expressions only have a fixed ordering of the"
                   " types of bindings without interleaving, except that"
                   " global bindings are allowed before all other bindings"
                   " and after all bindings. If you have global bindings"
                   " in the middle of non-global bindings or any other"
                   " interleaving then you will need to reorder all your"
                   " bindings for that feature and direction."
                   " Refer to nspepi documentation.")
# store registered methods to be called for parsed CLI commands
dispatchtable = collections.defaultdict(list)
# store registered methods to be called at end of processing CLI commands
final_methods = []
# store registered methods to be called before the start of processing of
# CLI commands.
init_methods = []
# store registered methods to be called for vserver/service/user/group
# bindings.
# Two level dictionary: bind_table[bind_cmd_module][policy_type]
bind_table = collections.OrderedDict()


class DispatchData(object):
    """
    Store object and method to dispatch call to for parsed CLI command.
    """
    def __init__(self, o, m):
        self.obj = o
        self.method = m


def register_class_methods(cls):
    """
    Decorator that registers the tagged methods within the class.
    NOTE: Class MUST BE decorated with this if it has methods decorated by
          by decorators in this module otherwise they won't be registered!
          Also, decorate base class with this as well if it has methods
          decorated by decorators in this module.

    Args:
        cls: The class to be processed for tagged methods.

    Returns:
        cls: The class itself that was passed in as an argument.
    """
    obj = cls()
    class_name = obj.__class__.__name__
    for name, method in cls.__dict__.items():
        if hasattr(method, "register_for_cmd"):
            for cmd in getattr(method, "cmd_list"):
                key = " ".join([cmd['op'], cmd['group'], cmd['ot']]).lower()
                dispatchtable[key].append(DispatchData(obj, method))
        if hasattr(method, "register_for_final_call"):
            final_methods.append(DispatchData(obj, method))
        if hasattr(method, "register_for_bind"):
            for bind_module in getattr(method, "module_list"):
                if bind_module not in bind_table:
                    bind_table[bind_module] = collections.OrderedDict()
                bind_table[bind_module][class_name] = DispatchData(obj, method)
        if hasattr(method, "register_for_init_call"):
            init_methods.append(DispatchData(obj, method))
    return cls


def register_for_cmd(op, group, ot):
    """
    Decorator that tags a method to be registered to process a command.
    NOTE: This decorator MUST BE the outermost decorator used on a method
          decorated with multiple decorators! The custom user attributes
          of a method aren't preserved in python 2.7 even with use of
          wraps() from functools.

    Args:
        op: Operation of command such as "add", "bind", etc.
        group: Group of command such as "lb", "responder", etc.
        ot: Object type of command such as "vserver", "policy", etc.

    Returns:
        m: The same method itself as passed in the arguments but with
           additional user attributes set within the method. These
           custom attributes are processed afterwards within the class
           decorator. Once all of the decorators on the methods within
           the class are executed and all of the methods and data in
           the class is parsed then the class is formed and available.
           At that time the class decorator gets called on the class
           where these tagged methods by decorators like these are
           processed.
    """
    def wrapper(m):
        if not hasattr(m, "register_for_cmd"):
            m.cmd_list = []
        m.register_for_cmd = True
        cmd = {'op': op, 'group': group, 'ot': ot}
        m.cmd_list.append(cmd)
        return m
    return wrapper


def register_for_final_call(m):
    """
    Decorator that tags a method to be called at the end of processing cmds.
    NOTE: This decorator MUST BE the outermost decorator used on a method
          decorated with multiple decorators! The custom user attributes
          of a method aren't preserved in python 2.7 even with use of
          wraps() from functools.

    Args:
        m: Method to be tagged to call at end of processing

    Returns:
        m: The same method itself as passed in the arguments but with
           additional user attributes set within the method. These
           custom attributes are processed afterwards within the class
           decorator. Once all of the decorators on the methods within
           the class are executed and all of the methods and data in
           the class is parsed then the class is formed and available.
           At that time the class decorator gets called on the class
           where these tagged methods by decorators like these are
           processed.
    """
    m.register_for_final_call = True
    return m


def register_for_init_call(m):
    """
    Decorator that tags a method to be called at the end of processing cmds.
    NOTE: This decorator MUST BE the outermost decorator used on a method
          decorated with multiple decorators! The custom user attributes
          of a method aren't preserved in python 2.7 even with use of
          wraps() from functools.

    Args:
        m: Method to be tagged to call at the start of processing

    Returns:
        m: The same method itself as passed in the arguments but with
           additional user attributes set within the method. These
           custom attributes are processed afterwards within the class
           decorator. Once all of the decorators on the methods within
           the class are executed and all of the methods and data in
           the class is parsed then the class is formed and available.
           At that time the class decorator gets called on the class
           where these tagged methods by decorators like these are
           processed.
    """
    m.register_for_init_call = True
    return m


def register_for_bind(module_list):
    """
    Decorator that tags a method to be registered to process a command.
    NOTE: This decorator MUST BE the outermost decorator used on a method
          decorated with multiple decorators! The custom user attributes
          of a method aren't preserved in python 2.7 even with use of
          wraps() from functools.

    Args:
        module_list: List of all other module names where all present
                     module policy can be bound.

    Returns:
        m: The same method itself as passed in the arguments but with
           additional user attributes set within the method. These
           custom attributes are processed afterwards within the class
           decorator. Once all of the decorators on the methods within
           the class are executed and all of the methods and data in
           the class is parsed then the class is formed and available.
           At that time the class decorator gets called on the class
           where these tagged methods by decorators like these are
           processed.
    """
    def wrapper(m):
        m.register_for_bind = True
        m.module_list = module_list
        return m
    return wrapper


def dict_repr(obj):
    """
    Creates an unambiguous and consistent representation of a dictionary.

    Args:
        obj: The dictionary to produce the representation of

    Returns:
        The string representation
    """
    result = '{'
    for key in sorted(obj):
        elem = obj[key]
        if isinstance(elem, dict):
            result += repr(key) + ': ' + dict_repr(elem) + ', '
        else:
            result += repr(key) + ': ' + repr(elem) + ', '
    if result.endswith(', '):
        result = result[0:-2]
    result += '}'
    return result


def class_repr(obj):
    """
    Creates an unambiguous and consistent representation of a class.

    Args:
        obj: The class object to produce the representation of

    Returns:
        The string representation
    """
    return '<' + type(obj).__name__ + ' ' + dict_repr(obj.__dict__) + '>'


def get_cmd_arg(arg, cmd_tree):
    """
    Return the indicated command argument from command parse tree. If arg is
    a str it is a keyword. If arg is an int it is a positional index. If
    the argument is not found, return None.

    Args:
        arg: Command argument to look up
        cmd_tree: Parsed command tree

    Returns:
        value: Value of the command argument or None if not found
    """
    value = None
    if isinstance(arg, int):
        node = cmd_tree.positional_value(arg)
        if node is not None:
            value = node.value
    elif isinstance(arg, str):
        if cmd_tree.keyword_exists(arg):
            value = cmd_tree.keyword_value(arg)[0].value
    else:
        assert False, ("get_cmd_arg(arg, cmd_tree): arg {} not an instance of"
                       " int or str".format(arg))
    return value


class Group(object):
    """
    Represents a group command based on a parsed command and provides
    methods to read and set info based on analysis.
    """
    def __init__(self, name="", weight="0"):
        """
        Construct object based on parsed group command parameters.

        Args:
            name: Name of the group
            weight: Weight of the group
        """
        self.name = name
        self.weight = weight

    def __repr__(self):
        """ Creates an unambiguous representation of the Group object.

        Returns:
            str: the string representation
        """
        return class_repr(self)


class Policy(object):
    """
    Represents a policy command based on a parsed command and provides
    methods to read and set info based on analysis.
    """
    def __init__(self, name="", module="", policy_type=""):
        """
        Construct object based on parsed policy command parameters.

        Args:
            name: Name of the policy
            module: Unambiguated name of the group of the policy
                    (ex. responder, TMSession for tm sessionPolicy, etc.)
            policy_type: Type of the policy ("classic" or "advanced")
        """
        self.name = name
        self.module = module
        self.policy_type = policy_type

    def __repr__(self):
        """ Creates an unambiguous representation of the Policy object.

        Returns:
            str: the string representation
        """
        return class_repr(self)


class Bind(object):
    """
    Represents a bind command based on a parsed command and provides
    methods to read and set info based on analysis.
    """
    def __init__(self, entity, entity_type, entity_name, policy_name,
                 policy_module, bind_type, priority, cmd_str, global_type="",
                 lineno="0"):
        """
        Construct object based on parsed bind command parameters.

        Args:
            entity: OT of the command (ex. vserver, user, group, service)
            entity_type: Group of the command (ex. lb, cs, cr, ssl, aaa)
            entity_name: Name of the entity (None if global)
            policy_name: Name of the bound policy
            policy_module: Module of the bound policy
            bind_type: Type of the bind (ex. request, response, etc.)
            priority: Priority of the bind command
            cmd_str: String representation of the bind command
            global_type: Suggested global type based on analysis
                         (override or default or "")
            lineno: Line number of the original bind command in config file
        """
        self.entity = entity
        self.entity_type = entity_type
        self.entity_name = entity_name
        self.policy_name = policy_name
        self.policy_module = policy_module
        self.bind_type = bind_type
        self.priority = priority
        self.cmd_str = cmd_str
        self.global_type = global_type
        self.lineno = lineno

    def __repr__(self):
        """ Creates an unambiguous representation of the Bind object.

        Returns:
            str: the string representation
        """
        return class_repr(self)


class PoliciesAndBinds(object):
    """
    Holds policies and bind info for analysis. For ex. to detect if
    a non-global priority has a lower number than a global priority
    that in turn is a lower number priority than a priority for the
    same non-global bind point.
    """
    # Specify sort order below for use in priority analysis methods
    # below to sort binds at the same priority in this order and
    # also to determine whether the binds conform to this order
    # to detect interleaving
    ORDER = ["global", "user", "group", "vpn", "lb", "cs", "cr", "service",
             "global"]
    # List of the policy modules for which global override
    # should be skipped.
    skip_global_override = []
    # dictionary that holds groups
    # key: name of group
    # value: Group object
    groups = collections.defaultdict(lambda: Group())
    # dictionary that holds policies
    # key: name of policy
    # value: Policy object
    policies = collections.defaultdict(lambda: Policy())
    # dictionary that holds global bind commands for analysis
    # global_binds[<module>][<bind_type>]
    # key: policy module of bound policy (ex. responder, appfw, etc.)
    # value: another dictionary with:
    #        key: bind_type (ex. request/response)
    #        value: list of Bind objects representing bind command
    global_binds = collections.defaultdict(  # module
        lambda: collections.defaultdict(list))  # bind_type
    # dictionary that holds entity bind commands for analysis
    # entity_binds[<entity>][<entity_type>][<entity_name>][<module>]
    #                                                     [<bindtype>]
    # key: entity (ex. vserver, user, group, service, global)
    # value: another dictionary with:
    #        key: entity_type (ex. lb, cs, cr, ssl, vpn, authorization, aaa)
    #        value: another dictionary with:
    #               key: entity_name (name of bind entity)
    #               value: another dictionary with:
    #                      key: module (module of bound policy)
    #                      value: another dictionary with:
    #                             key: bind_type (ex. request/response)
    #                             value: list of Bind objects
    entity_binds = collections.defaultdict(  # entity
        lambda: collections.defaultdict(  # entity_type
            lambda: collections.defaultdict(  # entity_name
                lambda: collections.defaultdict(  # module
                    lambda: collections.defaultdict(list)))))  # bind_type
    # dictionary that holds analysis results for bind commands
    # key: str representation of original bind command
    # value: another dictionary with:
    #        key: analysis result name for bind command
    #        value: analysis result value for bind command
    #        ex. key: "unsupported", value: True
    priority_analysis_results = collections.defaultdict(  # bind cmd
        lambda: collections.defaultdict())  # dict of results

    def __init__(self):
        pass

    @staticmethod
    def add_to_skip_global_override(module_name):
        """
        Adds policy module name to the list for which
        global override should be skipped.
        module_name - Policy module name
        """
        PoliciesAndBinds.skip_global_override.append(module_name)

    @staticmethod
    def get_skip_global_override():
        """
        Returns the list of modules for which global
        override should be skipped.
        """
        return PoliciesAndBinds.skip_global_override

    def store_group(self, groupobj):
        """
        Store group object representing group command for analysis.

        Args:
            groupobj: Group object representing group command
        """
        PoliciesAndBinds.groups[groupobj.name] = groupobj
        logging.debug("Stored group: {}".format(groupobj))

    def get_group(self, groupname):
        """
        Returns the group object for the passed in groupname.

        Args:
            groupname: Name of the group to look up
        """
        return PoliciesAndBinds.groups[groupname]

    def store_policy(self, policyobj):
        """
        Store policy object representing policy command for analysis.

        Args:
            policyobj: Policy object representing policy command
        """
        PoliciesAndBinds.policies[policyobj.name] = policyobj
        logging.debug("Stored policy: {}".format(policyobj))

    def get_policy(self, policyname):
        """
        Returns the policy object for the passed in policyname.

        Args:
            policyname: Name of the policy to look up
        """
        return PoliciesAndBinds.policies[policyname]

    def store_original_bind(self, bindobj):
        """
        Store bind object representing bind command for analysis.

        Args:
            bindobj: Bind object representing bind command
        """
        if (bindobj.policy_name in PoliciesAndBinds.policies
            and PoliciesAndBinds.policies[bindobj.policy_name].policy_type
                == "classic"):
            logging.debug("Stored bind: {}".format(bindobj))
            if bindobj.entity == "global":
                (PoliciesAndBinds.global_binds
                    [bindobj.policy_module][bindobj.bind_type]).append(bindobj)
            else:
                (PoliciesAndBinds.entity_binds
                    [bindobj.entity][bindobj.entity_type][bindobj.entity_name]
                    [bindobj.policy_module][bindobj.bind_type]).append(bindobj)

    def do_priority_analysis(self, global_list, local_list,
                             skip_global_override=False):
        """
        Do priority analysis and return list of binds that cannot be converted
        for a particular module and bind_type.

        Args:
            global_list: List of global binds per module and bindtype
            local_list: List of local binds per entitytype and module
                        and bindtype
            skip_global_override: Whether to skip global override
                                  or not in analysis.

        Returns:
            res: List of unsupported binds
            res_gtypes: List of Bind objects with suggested 'global_type'
                        as "override" or "default" based on analysis
        """
        res = []
        res_gtypes = []
        state = 1 if skip_global_override else 0
        states = ["global", "local", "global"]
        g_types = ["override", "", "default"]
        # store globals and locals combined in dictionary by priority
        # key: priority
        # value: list of bind object(s)
        combined = collections.defaultdict(list)
        [combined[int(o.priority)].append(o) for o in local_list + global_list]
        # go through sorted combined list of priorities and determine if the
        # bindings fall under globals (override) followed by locals and
        # then by globals (default) based on priority
        for prio in sorted(combined.keys()):
            # there could be multiple binds at the same priority
            # so go through each in order
            for o in combined[prio]:
                s = "global" if o.entity == "global" else "local"
                # if type of prev priority or prev bind differs from curr then
                # go to next type/state.
                if s != states[state]:
                    if (state + 1) < len(states):
                        state += 1
                    else:
                        # no more valid states so all priorities including
                        # and after current priority cannot be converted
                        res.extend(combined[prio])
                        break
                o.global_type = g_types[state]
                res_gtypes.append(o)
        logging.debug("do_priority_analysis(): ")
        logging.debug("\nglobals: {}\n\nlocals: {}\n\nunsupported: {}"
                      "".format(global_list, local_list, res))
        return res, res_gtypes

    def analyze_vserver_priorities(self):
        """
        Analyze priorities of all classic policies bound to global against
        vserver entities. The goal is to detect if any classic policy bind
        cannot be converted to global override, local, or global default
        while preserving their original priorities. For those classic policy
        binds that can't be converted their analysis results are stored in
        priority_analysis_results.
        """
        # store list of unsupported binds after analysis
        unsupported = set()
        # store list of bind objects with updated 'global_type'
        updated_global_types = []
        # store list of merged binds for a particular entity_type
        local_binds = collections.defaultdict(  # entity_type (ex. lb or cs)
            lambda: collections.defaultdict(  # module
                lambda: collections.defaultdict(list)))  # bind_type
        # iterate through all binds and merge all binds for a particular
        # entity_type per module and bind_type in local_binds.
        # i.e. combine entries for all VServers together,
        # keeping all other dimensions separate.
        ebinds = PoliciesAndBinds.entity_binds
        entity = "vserver"
        for entity_type in ebinds[entity]:
            for vs in ebinds[entity][entity_type]:
                for module in ebinds[entity][entity_type][vs]:
                    for bind_type in ebinds[entity][entity_type][vs][module]:
                        local_binds[entity_type][module][bind_type] += (
                            ebinds[entity][entity_type][vs][module][bind_type])
        logging.debug("Local binds: {}".format(local_binds))
        # if a module only contains global binds or local binds then
        # they can all be converted. However, if both global and local
        # binds exist for a module then analyze them to determine if
        # conversion is possible or not and store analysis results.
        gbinds = PoliciesAndBinds.global_binds
        for gmodule in gbinds:
            for gbind_type in gbinds[gmodule]:
                locals_list = []
                if local_binds:
                    for entity_type in local_binds:
                        if (gmodule in local_binds[entity_type] and gbind_type
                                in local_binds[entity_type][gmodule]):
                            # module and bind_type match for global and local
                            locals_list += (
                                 local_binds[entity_type][gmodule][gbind_type])
                logging.debug(
                    "do_priority_analysis() for {} {}"
                    "".format(gmodule, gbind_type))
                unsupp, updated_gtypes = self.do_priority_analysis(
                                          gbinds[gmodule][gbind_type], locals_list,
                                          gmodule in PoliciesAndBinds.
                                          get_skip_global_override())
                unsupported.update(unsupp)
                updated_global_types += updated_gtypes
        # store analysis results
        res = PoliciesAndBinds.priority_analysis_results
        for bindobj in unsupported:
            res[bindobj.cmd_str]["unsupported"] = True
        for bindobj in updated_global_types:
            res[bindobj.cmd_str]['global_type'] = bindobj.global_type

    @staticmethod
    def get_entity_state_name(o):
        """
        Returns the computed name for the state of the passed-in bind object
        for use in priority analysis.

        Args:
            o - Bind object
        """
        return o.entity if (o.entity == "global" or o.entity == "user"
                            or o.entity == "group") else o.entity_type

    @staticmethod
    def entity_key(o):
        """
        Return key for use in sorting all bind entities in order of
        user, group, vpn, lb, cs, service and global at the same
        priority for interleaving priority analysis.

        Args:
            o - Bind object to determine key for sort
        """
        # removing global from the beginning because at the same priority
        # there's no concept of global override and global default. Based on
        # investigation the globals always came after the locals so
        # that's why global is only at the end here.
        order = PoliciesAndBinds.ORDER[1:]
        name = PoliciesAndBinds.get_entity_state_name(o)
        return -1 if name not in order else order.index(name)

    def do_priority_analysis_for_all_entities(
            self, global_list, local_list, skip_global_override=False):
        """
        Do priority analysis and return list of binds that cannot be converted
        for a single module and bindtype.

        Args:
            global_list: List of global binds per module and bindtype
            local_list: List of all local binds per module and bindtype
            skip_global_override: Whether to skip global override
                                  or not in analysis

        Returns:
            res: List of unsupported binds
        """
        res = []
        state = 1 if skip_global_override else 0
        # "global" is at the beginning of the list to account for global
        # override. Based on investigation the globals always
        # came after the locals so that's why globals are put at the end
        # in "ORDER". In case of priority 0 with multiple local binds as
        # well at priority 0 all of the globals can be converted to be
        # global default. The reason for global being at the front here
        # is because if there are only global binds at a single priority
        # then they can be converted to be global override. More importantly
        # if there are globals of low numbered priority then all locals after
        # that in priority and then globals after that in priority we can
        # also support that using a combination of global override and
        # global default.
        states = PoliciesAndBinds.ORDER
        # store globals and locals combined in dictionary by priority
        # key: priority
        # value: list of bind object(s)
        combined = collections.defaultdict(list)
        [combined[int(o.priority)].append(o) for o in local_list + global_list]
        # go through sorted combined list of priorities and determine if the
        # bindings fall under the order specified above in variable "states"
        for prio in sorted(combined.keys()):
            # there could be multiple binds at the same priority
            # so go through each in sorted order based on order
            # specified above in variable "states"
            for o in sorted(combined[prio], key=PoliciesAndBinds.entity_key):
                s = PoliciesAndBinds.get_entity_state_name(o)
                # if entity of prev priority or prev bind differs from curr
                # then go to next type/state
                if s != states[state]:
                    # if entity's group/"state" is not applicable then skip
                    # for cr, gslb and authentication. Evaluation for them
                    # only involve globals and don't support combination
                    # with others.
                    if s not in states:
                        continue
                    # if curr bind is of a prev entity group/"state" that
                    # has already been processed then mark as unsupported.
                    # Obtain index of current state from states but for
                    # global pick the first ("override") and last ("default")
                    # correctly based on whether current state is past
                    # global "override" by passing in the start index
                    # as 0 if current state is at global "override" or 1
                    # if current state is past global "override" to pick
                    # global "default" for current state of "global".
                    state_index = states.index(s, 0 if state == 0 else 1)
                    if state_index < state:
                        logging.debug("state {} for {} is already processed"
                                      " as current state is at {} so marking"
                                      " as unsupported"
                                      "".format(s, o.cmd_str, states[state]))
                        res.append(o)
                        continue
                    # go to next state if possible and check if curr bind
                    # falls under that
                    while s != states[state]:
                        if (state + 1) < len(states):
                            state += 1
                        else:
                            # no more valid states so all binds at current
                            # priority and after cannot be converted
                            logging.debug("no more valid states so marking"
                                          " as unsupported for {}"
                                          "".format(o.cmd_str))
                            res.append(o)
                            break
        logging.debug("do_priority_analysis_for_all_entities(): ")
        logging.debug("\nglobals: {}\n\nlocals: {}\n\nunsupported: {}"
                      "".format(global_list, local_list, res))
        return res

    def analyze_multiple_entities_for_interleaving_priorities(self):
        """
        Analyze priorities of all classic policies bound to global against
        all entities for interleaving priorities. The goal is to detect if
        any classic policy bind cannot be converted to global override,
        user, group, vpn, lb, cs, service, global default in that order
        while preserving their original priorities. For those classic policy
        binds that can't be converted their analysis results are stored in
        priority_analysis_results.
        """
        # store list of unsupported binds after analysis
        unsupported = set()
        # store list of merged binds for all entity_types
        local_binds = collections.defaultdict(  # module of policy
            lambda: collections.defaultdict(list))  # bind_type
        # iterate through all binds and merge all binds for each module and
        # bind_type in local_binds.
        # i.e. combine entries for all VServers and types of entities
        # together, keeping all other dimensions separate.
        ebinds = PoliciesAndBinds.entity_binds
        for entity in ebinds:
            for entity_type in ebinds[entity]:
                for vs in ebinds[entity][entity_type]:
                    for module in ebinds[entity][entity_type][vs]:
                        for bind_type in (ebinds
                                          [entity][entity_type][vs][module]):
                            local_binds[module][bind_type] += (
                                ebinds
                                [entity][entity_type][vs][module][bind_type])
        logging.debug("analyze_multiple_entities_for_interleaving_priorities:")
        logging.debug("Local binds: {}".format(local_binds))
        # if a module contains only global binds then they can all be
        # converted. However, if only local binds or both global and local
        # binds exist for a module then analyze them to determine if
        # conversion is possible or not and store analysis results.
        gbinds = PoliciesAndBinds.global_binds
        for module in local_binds:
            for bind_type in local_binds[module]:
                globals_list = []
                if module in gbinds and bind_type in gbinds[module]:
                    # module and bind_type match for both global and local
                    globals_list += gbinds[module][bind_type]
                logging.debug(
                    "self.do_priority_analysis_for_all_entities() for {} {}"
                    "".format(module, bind_type))
                unsupported.update(
                    self.do_priority_analysis_for_all_entities(
                        globals_list, local_binds[module][bind_type],
                        module in PoliciesAndBinds.
                        get_skip_global_override()))
        # store analysis results
        res = PoliciesAndBinds.priority_analysis_results
        for bindobj in unsupported:
            res[bindobj.cmd_str]["unsupported"] = True

    def do_priority_analysis_for_all_users_groups(self, user_list, group_list):
        """
        Do priority analysis for all users and groups and return list of binds
        that cannot be converted for a single module and bindtype.
        Check for and handle the following cases:
        1. Mark bind as unsupported for any user bind that comes after a group
           bind in priority
        2. Mark bind as unsupported for any earlier group bind that comes
           after a different group bind in priority. This is to detect any
           interleaving between groups.
        3. Mark bind as unsupported for any group bind that conflicts with
           the weight of the group. In advanced policy evaluation groups
           are evaluated in order of their weight so detect if any classic
           binds are at priorities contradictory to the groups' weights.
        4. Check if any groups have the same weight and give an error

        Args:
            user_list: List of user binds per module and bindtype
            group_list: List of group binds per module and bindtype

        Returns:
            res: List of unsupported binds
        """
        res = set()
        state = 0
        states = ["user", "group"]
        # store users and groups combined in dictionary by priority
        # key: priority
        # value: list of bind object(s)
        combined = collections.defaultdict(list)
        [combined[int(o.priority)].append(o) for o in user_list + group_list]
        # check for case #1 described in method comments above
        # go through sorted combined list of priorities and determine if the
        # bindings fall under the order specified above in variable "states"
        for prio in sorted(combined.keys()):
            # there could be multiple binds at the same priority
            # so go through each in sorted order based on order
            # specified above in variable "states"
            for o in sorted(combined[prio],
                            key=lambda b: states.index(b.entity)):
                s = o.entity
                # if entity of prev priority or prev bind differs from curr
                # then go to next type/state
                if s != states[state]:
                    # if curr bind is of a prev "state" that has already been
                    # processed then mark as unsupported. This is to handle
                    # case #1 described in method comments above.
                    if states.index(s) < state:
                        logging.debug("state {} for {} is already processed"
                                      " as current state is at {} so marking"
                                      " as unsupported"
                                      "".format(s, o.cmd_str, states[state]))
                        res.add(o)
                        continue
                    # go to next state if possible and check if curr bind
                    # falls under that
                    while s != states[state]:
                        if (state + 1) < len(states):
                            state += 1
                        else:
                            # no more valid states so all binds at current
                            # priority and after cannot be converted
                            logging.debug("no more valid states so marking"
                                          " as unsupported for {}"
                                          "".format(o.cmd_str))
                            res.add(o)
                            break
        # check for case #2 described in method comments above
        # store groups in dictionary by priority
        # key: priority
        # value: list of group bind object(s)
        groups = collections.defaultdict(list)
        [groups[int(o.priority)].append(o) for o in group_list]
        # store list of groups that have already been processed
        # at earlier priorities
        earlier = [""]
        # go through sorted group list of priorities and determine if
        # any earlier group bind comes after a different group bind
        # indicating interleaving between groups
        for prio in sorted(groups.keys()):
            # there could be multiple binds at the same priority
            # so go through each in sorted order based on ns.conf order
            # and check for interleaving.
            for o in sorted(groups[prio], key=lambda o: int(o.lineno)):
                if o.entity_name in earlier and o.entity_name != earlier[-1]:
                    logging.debug("group {} for {} is already processed"
                                  " earlier so marking as unsupported"
                                  "".format(o.entity_name, o.cmd_str))
                    res.add(o)
                    continue
                elif o.entity_name != earlier[-1]:
                    earlier.append(o.entity_name)
        # store max weight seen for groups processed
        max_weight = 0
        # check for case #3 described in method comments above
        # go through sorted group list of priorities and determine
        # if the weights of the group are in contradictory order
        # to the priorities
        for prio in sorted(groups.keys()):
            # there could be multiple binds at the same priority
            # so go through each and check for interleaving.
            for o in sorted(groups[prio], key=lambda o: int(o.lineno)):
                # lower numbered weights indicate higher preference of the
                # group compared to higher numbered weights
                w = int(self.get_group(o.entity_name).weight)
                # at increasing priorities if there's a group encountered
                # whose weight is less than the largest group weight seen
                # of groups at earlier priorities then mark it as
                # unsupported
                if w < max_weight:
                    logging.debug("group {} for {} has weight {} less than"
                                  " max weight {} for an earlier group so"
                                  " marking as unsupported"
                                  "".format(
                                      o.entity_name, o.cmd_str, w, max_weight))
                    res.add(o)
                    continue
                elif w > max_weight:
                    max_weight = w
        # check for case #4 described in method comments above
        # go through sorted group list in order weights and give
        # an error if more than one group has the same weight
        weights = collections.defaultdict(set)
        [weights[int(self.get_group(o.entity_name).weight)].add(o)
            for o in group_list]
        for v in weights.values():
            same_weight_group_set = set([o.entity_name for o in v])
            if len(same_weight_group_set) > 1:
                logging.error("Groups: {} having the same weight and bindings"
                              " have no defined ordering in Advanced Policy"
                              " evaluation.".format(
                                  ", ".join(sorted(same_weight_group_set))))
                res.update(v)
        logging.debug("do_priority_analysis_for_all_users_groups(): ")
        logging.debug("\nusers: {}\n\ngroups: {}\n\nunsupported: {}"
                      "".format(user_list, group_list, res))
        return res

    def analyze_user_group_priorities(self):
        """
        Analyze user and group priorities.
        """
        # store list of unsupported binds after analysis
        unsupported = set()
        # store list of merged binds for all users
        user_binds = collections.defaultdict(  # module of policy
            lambda: collections.defaultdict(list))  # bind_type
        # store list of merged binds for all groups
        group_binds = collections.defaultdict(  # module of policy
            lambda: collections.defaultdict(list))  # bind_type
        # iterate through all binds and merge all binds for each module and
        # bind_type in user_binds and group_binds.
        # i.e. combine entries for all users and groups
        # respectively, keeping all other dimensions separate.
        ebinds = PoliciesAndBinds.entity_binds
        for entity in ["user", "group"]:
            for entity_type in ebinds[entity]:
                for name in ebinds[entity][entity_type]:
                    for module in ebinds[entity][entity_type][name]:
                        for bind_type in (ebinds
                                          [entity][entity_type][name][module]):
                            if entity == "user":
                                user_binds[module][bind_type] += (
                                    ebinds[entity][entity_type][name][module]
                                    [bind_type])
                            elif entity == "group":
                                group_binds[module][bind_type] += (
                                    ebinds[entity][entity_type][name][module]
                                    [bind_type])
        logging.debug("analyze_user_group_priorities():")
        logging.debug("user binds: {}".format(user_binds))
        logging.debug("group binds: {}".format(group_binds))
        # if a module contains only user binds then they can all be
        # converted. However, if only group binds or both user and group
        # binds exist for a module then analyze them to determine if
        # conversion is possible or not and store analysis results.
        for module in group_binds:
            for bind_type in group_binds[module]:
                user_list = []
                if module in user_binds and bind_type in user_binds[module]:
                    # module and bind_type match for both group and user
                    user_list += user_binds[module][bind_type]
                logging.debug(
                    "do_priority_analysis_for_all_users_groups() for {} {}"
                    "".format(module, bind_type))
                unsupported.update(
                    self.do_priority_analysis_for_all_users_groups(
                        user_list, group_binds[module][bind_type]))
        # store analysis results
        res = PoliciesAndBinds.priority_analysis_results
        for bindobj in unsupported:
            res[bindobj.cmd_str]["unsupported"] = True

    def analyze(self):
        """
        Run analysis methods on PoliciesAndBinds.
        """
        self.analyze_vserver_priorities()
        self.analyze_user_group_priorities()
        self.analyze_multiple_entities_for_interleaving_priorities()

    def is_bind_unsupported(self, orig_bind_str):
        """
        Determine if bind is unsupported for passed in bind command string.

        Args:
            orig_bind_str: Bind command string of original bind command read
                           from config

        Returns:
            result: Priority analysis result for passed in bind command or
                    None if no result is present for it
        """
        result = None
        res = PoliciesAndBinds.priority_analysis_results
        if orig_bind_str in res and "unsupported" in res[orig_bind_str]:
            result = res[orig_bind_str]["unsupported"]
        return result

    def get_global_type_for_bind(self, orig_bind_str):
        """
        Return the global type based on analysis for passed in bind command
        string.

        Args:
            orig_bind_str: Bind command string of original bind command read
                           from config

        Returns:
            result: Global type based on analysis result for passed in bind
                    command or None if no result is present for it
        """
        result = None
        res = PoliciesAndBinds.priority_analysis_results
        if orig_bind_str in res and "global_type" in res[orig_bind_str]:
            result = res[orig_bind_str]["global_type"]
        return result


# store all policies and any associated binds for analysis
pols_binds = PoliciesAndBinds()
