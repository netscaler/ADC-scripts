#!/usr/bin/env python

# Copyright 2021-2023 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

'''
Note:
    1. If action has value as prebody or postbody then there will not be any conversion
    2. If policy bind command has parameter "state disabled" then converted bind command will be commented out
    3. Filter feature of actionType FORWARD is not supported currently
    4. bind command of filter policies gets complicated if ns.conf already contains vserver of ptotocol type HTTP/S and rewrite/responder policy bindings:
       1. If goto is END/USE_INVOCATION_RESULT exists in existing rewrite local bindings and|not global bindings
       2. If goto is END/USE_INVOCATION_RESULT exists in existing rewrite global bindings and|not local bindings
       Then comment out all partially converted rewrite global and local bindings otherwise do proper convertion.
       Same applies for responder conditions.

---INPUT WITH ADD ACTIONTYPE---
add filter action act1 ADD "H1:Value"
add filter action act2 ADD "H1:::::Value"
add filter action act3 ADD H1::::::Value
add filter action act4 ADD H1:
add filter action act5 ADD H1::
add filter action act6 ADD "H1:::"
add filter action act7 ADD "abcd:\"d1\""
add filter action act8 ADD "abcd:::::::\"d1\""
add filter action act10 ADD "@5%^&:Vl54"
add filter action act11 ADD q/\t:123/
add filter action act12 ADD q/Name:\t/
add filter action act13 ADD q/Name:\\t/
add filter action act14 ADD prebody:123
add filter action act15 ADD postbody:1234
add filter action act16 ADD "\"H1:grv\""
add filter action act17 ADD "/H1/:/d/1"
add filter action act18 ADD "/H1/:d/1"
add filter action act20 ADD "\H1:d1"
add filter action act21 add "/\H1:d1"
add filter action act22 ADD "\\\\H1:\\\d\\\\1\\\\2\\\\"
add filter action act23 add "H1:\\n"
add filter action act24 add "H\\n1:\\n"
add filter action act25 add "H    \n1:\\n"
add filter action act26 add "H1:Value1:Value2"
add filter action act27 add "H1:%%HTTP.TRANSID%%"
add filter action act28 add prebody
add filter action act29 add postbody
add filter policy add_pol1_1 -rule ns_true -resAction act1
add filter policy add_pol1_2 -rule ns_true -reqAction act1
add filter policy add_pol2_1 -rule ns_true -resAction act27
add filter policy add_pol2_2 -rule ns_true -reqAction act27
add filter policy add_pol3_1 -rule ns_true -reqAction act28
add filter policy add_pol3_2 -rule ns_true -resAction act28
add filter policy add_pol4_1 -rule ns_true -reqAction act29
add filter policy add_pol4_2 -rule ns_true -resAction act29
bind filter global add_pol1_1 [-priority <positive_integer>])
bind filter global add_pol1_2 [-priority <positive_integer>])
bind lb vserver <lb vs name> -policyName add_pol1_1 [-priority <positive_integer>])
bind lb vserver <lb vs name> -policyName add_pol1_2 [-priority <positive_integer>])
bind cs vserver <cs vs name> -policyName add_pol1_1 [-priority <positive_integer>])
bind cs vserver <cs vs name> -policyName add_pol1_2 [-priority <positive_integer>])
bind cr vserver <cr vs name> -policyName add_pol1_1 [-priority <positive_integer>])
bind cr vserver <cr vs name> -policyName add_pol1_2 [-priority <positive_integer>])
---CONVERTED RESULT---
add rewrite action act1 insert_http_header f_H1 "\"Value\""
add rewrite action act2 insert_http_header H1 "\"::::Value\""
add rewrite action act3 insert_http_header H1 "\":::::Value\""
add rewrite action act4 insert_http_header H1 "\"\""
add rewrite action act5 insert_http_header H1 "\":\""
add rewrite action act6 insert_http_header H1 "\"::\""
add rewrite action act7 insert_http_header abcd "\"\\\"d1\\\"\""
add rewrite action act8 insert_http_header abcd "\"::::::\\\"d1\\\"\""
add rewrite action act10 insert_http_header @5%^& "\"Vl54\""
add rewrite action act11 insert_http_header "\\t" "\"123\""
add rewrite action act12 insert_http_header Name "\"\\\\t\""
add rewrite action act13 insert_http_header Name "\"\\\\\\\\t\""
add rewrite action act14 insert_http_header prebody "\"123\""
add rewrite action act15 insert_http_header postbody "\"1234\""
add rewrite action act16 insert_http_header "\"H1" "\"grv\\\"\""
add rewrite action act17 insert_http_header /H1/ "\"/d/1\""
add rewrite action act18 insert_http_header /H1/ "\"d/1\""
add rewrite action act20 insert_http_header "\\H1" "\"d1\""
add rewrite action act21 insert_http_header "/\\H1" "\"d1\""
add rewrite action act22 insert_http_header "\\\\H1"
    "\"\\\\\\\\d\\\\\\\\1\\\\\\\\2\\\\\\\\\""
add rewrite action act23 insert_http_header H1 "\"\\\\n\""
add rewrite action act24 insert_http_header "H\\n1" "\"\\\\n\""
add rewrite action act25 insert_http_header "H    \n1" "\"\\\\n\""
add rewrite action act26 insert_http_header H1 "\"Value1:Value2\""
add rewrite action act27 insert_http_header H1 HTTP.REQ.TXID
add rewrite action nspepi_adv_act27 insert_http_header H1 HTTP.RES.TXID
add filter action act28 add prebody
add filter action act29 add postbody
add rewrite policy add_pol1_1 TRUE act1
add rewrite policy add_pol1_2 TRUE act1
add rewrite policy add_pol2_1 TRUE nspepi_adv_act27
add rewrite policy add_pol2_2 TRUE act27
add filter policy add_pol3_1 -rule ns_true -reqAction act28
add filter policy add_pol3_2 -rule ns_true -resAction act28
add filter policy add_pol4_1 -rule ns_true -reqAction act29
add filter policy add_pol4_2 -rule ns_true -resAction act29
bind rewrite global add_pol1_1 <positive priority integer> NEXT -TYPE RES_DEFAULT
bind rewrite global add_pol1_2 <positive priority integer> NEXT -TYPE REQ_DEFAULT
bind lb vserver <lb vs name> -policyName add_pol1_1 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE RESPONSE
bind lb vserver <lb vs name> -policyName add_pol1_2 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE REQUEST
bind cs vserver <cs vs name> -policyName add_pol1_1 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE RESPONSE
bind cs vserver <cs vs name> -policyName add_pol1_2 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE REQUEST
bind cr vserver <cr vs name> -policyName add_pol1_1 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE RESPONSE
bind cr vserver <cr vs name> -policyName add_pol1_2 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE REQUEST

---INPUT WITH CORRUPT ACTIONTYPE---
add filter action act30 CORRUPT TEST_HEADER
add filter policy corrupt_pol1_1 -rule ns_true -reqAction act30
add filter policy corrupt_pol1_2 -rule ns_true -resAction act30
bind filter global corrupt_pol1_1 [-priority <positive_integer>])
bind filter global corrupt_pol1_2 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName corrupt_pol1_1 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName corrupt_pol1_2 [-priority <positive_integer>])
---CONVERTED RESULT---
add rewrite action act30 corrupt_http_header TEST_HEADER
add rewrite policy corrupt_pol1_1 TRUE act30
add rewrite policy corrupt_pol1_2 TRUE act30
bind rewrite global corrupt_pol1_1 <positive priority integer> NEXT -TYPE REQ_DEFAULT
bind rewrite global corrupt_pol1_2 <positive priority integer> NEXT -TYPE RES_DEFAULT
bind lb vserver <lb vs name> -policyName corrupt_pol1_1 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE REQUEST
bind lb vserver <lb vs name> -policyName corrupt_pol1_2 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE RESPONSE

---INPUT WITH ERRORCODE ACTIONTYPE---
add filter action act1 ERRORCODE 200 "<HTML>Good URL</HTML>"
add filter action act2 ERRORCODE 200
add filter policy error_pol1 -rule ns_true -resAction act1
add filter policy error_pol2 -rule ns_true -reqAction act1
add filter policy error_pol3 -rule ns_true -resAction act2
bind filter global error_pol1 [-priority <positive_integer>])
bind filter global error_pol2 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName error_pol1 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName error_pol2 [-priority <positive_integer>])
---CONVERTED RESULT---
add responder action act1 respondwith "HTTP.REQ.VERSION.APPEND(\" 200 OK\r\n
   Connection: close\r\nContent-Length: 21\r\n\r\n<HTML>Good URL</HTML>\")"
add rewrite action nspepi_adv_act1 replace_http_res "HTTP.REQ.VERSION.APPEND
     (\" 200 OK\r\nConnection: close\r\nContent-Length: 21\r\n\r\n<HTML>
    Good URL</HTML>\")"
add responder action act2 respondwith "HTTP.REQ.VERSION.APPEND(\" 200 OK\r\n
    Connection: close\r\nContent-Length: 0\r\n\r\n\")"
add rewrite action nspepi_adv_act2 replace_http_res "HTTP.REQ.VERSION.APPEND
    (\" 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n\")"
add rewrite policy error_pol1 TRUE nspepi_adv_act1
add responder policy error_pol2 TRUE act1
add rewrite policy error_pol3 TRUE nspepi_adv_act2
bind rewrite global error_pol1 <positive priority integer> NEXT -TYPE RES_DEFAULT
bind rewrite global error_pol2 <positive priority integer> NEXT -TYPE REQ_DEFAULT
bind <lb|cs|cr> vserver <vs name> -policyName error_pol1 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE RESPONSE
bind <lb|cs|cr> vserver <vs name> -policyName error_pol2 [-priority <positive_integer>]) -gotoPriorityExpression END -TYPE REQUEST

---INPUT WITH DROP ACTION---
add filter action act1 DROP
add filter policy pol1 -rule "ns_true" -reqAction act1
add filter policy pol2 -rule "ns_true" -resAction act2
add filter policy pol3 -rule ns_true -reqAction DROP
add filter policy pol4 -rule ns_true -resAction DROP
bind filter global pol1 [-priority <positive_integer>])
bind filter global pol2 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName pol1 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName pol2 [-priority <positive_integer>])
---CONVERTED RESULT---
add responder policy pol1 TRUE DROP
add rewrite policy pol2 TRUE DROP
add responder policy pol3 TRUE DROP
add rewrite policy pol4 TRUE DROP
bind responder global pol1 <positive priority integer> END -type REQ_DEFAULT
bind rewrite global pol2 <positive priority integer> NEXT -type RES_DEFAULT
bind <lb|cs|cr> vserver <vs name> -policyName pol1 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE REQUEST
bind <lb|cs|cr> vserver <vs name> -policyName pol2 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE RESPONSE

---INPUT WITH RESET ACTION---
add filter action act1 RESET
add filter policy pol1 -rule "ns_true" -reqAction act1
add filter policy pol2 -rule "ns_true" -resAction act1
add filter policy pol3 -rule ns_true -reqAction RESET
add filter policy pol4 -rule ns_true -resAction RESET
bind filter global pol1 [-priority <positive_integer>])
bind filter global pol2 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName pol1 [-priority <positive_integer>])
bind <lb|cs|cr> vserver <vs name> -policyName pol2 [-priority <positive_integer>])
---CONVERTED RESULT---
add responder policy pol1 TRUE RESET
add rewrite policy pol2 TRUE RESET
add responder policy pol3 TRUE RESET
add rewrite policy pol4 TRUE RESET
bind responder global pol1 <positive priority integer> END -type REQ_DEFAULT
bind rewrite global pol2 <positive priority integer> NEXT -type RES_DEFAULT
bind <lb|cs|cr> vserver <vs name> -policyName pol1 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE REQUEST
bind <lb|cs|cr> vserver <vs name> -policyName pol2 [-priority <positive_integer>]) -gotoPriorityExpression NEXT -TYPE RESPONSE
'''

import re
import logging
import copy
import nspepi_common as common
from nspepi_parse_tree import *
from convert_classic_expr import *
from collections import OrderedDict
import convert_cli_commands as cli_cmds
from convert_lb_cmd import *
from itertools import chain
from convert_responder_command import Responder
from convert_rewrite_command import Rewrite


# All module names starting with "convert_" are parsed to detect and register
# class methods
@common.register_class_methods
class CLITransformFilter(cli_cmds.ConvertConfig):
    """
    Converts classic filter feature except htmlInjection and FORWARD type
    """
    flow_type_direction_default = None
    req_action_list = []
    res_action_list = []

    def __init__(self):
        """
        _action_command - Dictionary to store action name and converted classic
                   action commands of type 'errorcode' and 'add'
        _vserverName_list - List to store vserver names
        _actionTypeName - Dictionary to store
                {actionTypes: list of action names}
        _converted_pol_param - Dictionary to store- policyName: [re[sq]Action,
                   converted module, original_action_name]
        _policy_command - List to store converted actions which are called
                   by policy and policy commands itself for those which
                   has two converted actions for each classic action.
                   Otherwise store just converted policy commands
        _htmlInjection - List to store action names of those actions which
                   points to html injection values: prebody or postbody
        _bind_tree_rw - List of partially converted rewrite bind commands
                   to help in commenting out only converted rewrite binds if
                   existing rewrite has END/USE_INVOCATION_RESULT
        _bind_tree_resp - List of partially converted responder bind commands
                   to help in commenting out only converted responder binds
                   if existing responder has END/USE_INVOCATION_RESULT
        """
        self._action_command = OrderedDict()
        self._actionTypeName = OrderedDict([
            ("reset", ["reset"]), ("drop", ["drop"])])
        self._converted_pol_param = OrderedDict()
        self._policy_command = []
        self._htmlInjection = OrderedDict()
        self._htmlInjection["action"] = []
        self._htmlInjection["policy"] = []
        self._forward = OrderedDict()
        self._forward["action"] = []
        self._forward["policy"] = []
        self._bind_tree_rw = []
        self._bind_tree_resp = []
        self._policylabel_name = []
        self._policy_label_priority = OrderedDict()
        self.overlength_policy_names = {}
        self.overlength_policy_counter = 0
        self.overlength_policylabel_names = {}
        self.overlength_policylabel_counter = 0

    @common.register_for_cmd("add", "filter", "action")
    def convert_filter_action(self, action_parse_tree):
        """
        Transform classic feature for filter Action commands
         In case of actionType DROP and RESET:
         1. Store <DROP/RESET> to be used in transformed filter
            policy with action as <DROP/RESET>
         2. Remove "add filter action <action name> <DROP/RESET>"
            as this is not to be transformed to rewrite/responder,
            Only its actionType to be used in transformed policy.

         Information for variables used here:
             original_cmd - keeps the copy of classic command
             action_type - type of classic action
             actionName - name of original action
             header_value - refers to the value of Header when
                            action type is ADD
             Filter_variable - htmlInjection variable as key-value
                          pair example-{variable: [list of advance exp]}
             html_page - HTML page when action type is ERRORCODE
             content_length - indicates Content-Length
        """
        if cli_cmds.no_conversion_collect_data:
            return []
        original_cmd = copy.deepcopy(action_parse_tree)
        # Initialize tree to empty list.
        action_parse_tree_list = []
        action_type = original_cmd.positional_value(1).value.lower()
        if (action_type in [
             "add", "corrupt", "errorcode", "reset", "drop", "forward"]):
            """ Check if original command has filter group """

            # Store actionType and actionName
            actionName = original_cmd.positional_value(
                0).value
            lower_actionName = actionName.lower()
            if action_type not in self._actionTypeName:
                self._actionTypeName[action_type] = []
            self._actionTypeName[action_type].append(lower_actionName)

            if (action_type == "add"):
                """
                Transformation for classic command of actionType ADD
                KEY_POINTS:
                   1. Store input action name and list of 2 converted actions
                     for single input, only if input has html injection
                     variable as a value
                   2. Append new action name nspepi_adv_<input action name>
                     with input action name in actionTypeName dictionary
                     for above condition
                   3. return input command only if value in input is
                     prebody or postbody
                """
                header_value = original_cmd.positional_value(2).value
                if not ((header_value == "postbody") or (
                     header_value == "prebody")):
                    # Transformation for filter action of ADD as actionType
                    # if value is not pre/postbody
                    action_parse_tree = CLICommand("add", "rewrite", "action")
                    action_name = CLIPositionalParameter(actionName)
                    action_type_adv = CLIPositionalParameter(
                        "insert_http_header")
                    action_parse_tree.add_positional_list([
                        action_name, action_type_adv])

                    # Splitting classic action cmd value from 1st colon(:)
                    match = header_value.split(":", 1)
                    header = match[0]
                    value = match[1]
                    headerName = CLIPositionalParameter(header)
                    Filter_variable = {
                        'HTTP.TRANSID': ['HTTP.REQ.TXID', 'HTTP.RES.TXID'],
                        'HTTP.XID': ['HTTP.REQ.TXID', 'HTTP.RES.TXID']}

                    # Checks for Value/stringBuildExpression that has
                    # Html Injection Variable surrounded by %%
                    match_value = re.search(r"%%(.*)%%", value)
                    if not match_value:
                        stringBuildExp = CLIPositionalParameter(
                            action_parse_tree.normalize(value, True))
                        action_parse_tree.add_positional_list(
                            [headerName, stringBuildExp])
                        action_parse_tree.set_upgraded()
                        return [action_parse_tree]
                    else:
                        # if value of header is a variable surrounded between
                        # %%%%, then value is considered as HTMLInjection
                        # variable. That variable can be used in request and
                        # response sides, and value is generated based on the
                        # side. But, in the advanced policy expression, there are
                        # different expressions for the different sides. So,
                        # for each side an action needs to be created.
                        # rewrite_action_response: action which has HTTP.RES.XX
                        # action_parse_tree: action which has HTTP.REQ.XX

                        rewrite_action_response = copy.deepcopy(
                            action_parse_tree)
                        if match_value.group(1) in Filter_variable:
                            # Save action name in a list which is used to
                            # identify an action command
                            if lower_actionName not in self._action_command:
                                self._action_command[lower_actionName] = []
                            # Add a new rewrite action of different name whose
                            # stringBuildExpr should be expression of
                            # RESPONSE side
                            rewrite_action_response.positional_value(
                                0).set_value("nspepi_adv_" + actionName)
                            stringBuildExp_res = CLIPositionalParameter(
                                rewrite_action_response.normalize(
                                    Filter_variable[match_value.group(1)][1]))
                            rewrite_action_response.add_positional_list(
                                [headerName, stringBuildExp_res])
                            rewrite_action_response.set_upgraded()

                            # Modify current rewrite action where
                            # stringBuildExpr should be of REQUEST side
                            stringBuildExp_req = CLIPositionalParameter(
                                action_parse_tree.normalize(
                                    Filter_variable[match_value.group(1)][0]))
                            action_parse_tree.add_positional_list(
                                [headerName, stringBuildExp_req])
                            action_parse_tree.set_upgraded()

                            # Store actionName, and converted command
                            self._action_command[lower_actionName].append(
                                action_parse_tree)
                            self._action_command[lower_actionName].append(
                                rewrite_action_response)

                            # Store actionType and actionName
                            self._actionTypeName[action_type].append(
                                rewrite_action_response.positional_value(
                                    0).value.lower())
                            return []
                        else:
                            logging.error(
                                "Conversion of HTMLInjection variable in "
                                "command [{}] is not supported in this tool."
                                "".format(str(original_cmd).strip()))
                            return [action_parse_tree]

                else:
                    # Prebody/postbody value indicates that this config is
                    # being used for HTMLinjection feature, and conversion
                    # of HTMLinjection config is not supported, so return
                    # the input command as the output.

                    # Remove action name from stored dictionary.
                    self._actionTypeName[action_type].remove(lower_actionName)

                    # Store list of corresponding action names
                    self._htmlInjection["action"].append(actionName)
                    action_parse_tree_list = [original_cmd]
                    logging.error(
                        "Conversion of HTMLInjection feature related"
                        " command [{}] is not supported in this tool."
                        "".format(str(original_cmd).strip()))
            elif (action_type == "corrupt"):
                """
                Transformation for filter action of CORRUPT as actionType
                """
                action_parse_tree = CLICommand("add", "rewrite", "action")
                action_name = CLIPositionalParameter(actionName)
                action_type_adv = CLIPositionalParameter("corrupt_http_header")
                target = CLIPositionalParameter(
                    original_cmd.positional_value(2).value)
                action_parse_tree.add_positional_list([
                    action_name, action_type_adv, target])
                action_parse_tree.set_upgraded()
                action_parse_tree_list = [action_parse_tree]
            elif (action_type == "errorcode"):
                """
                Transformation for filter action of ERRORCODE as actionType.
                This transforms filter action to advanced command of
                both rewrite or/and responder features
                KEY-POINTS:
                  single input will be converted to 2 actions, one will have
                  nspepi_adv_ prefixed to name under rewrite module and
                  second will have its original name under responder module
                """
                req_side_needed = False
                res_side_needed = False
                req_side_name = actionName
                res_side_name = actionName
                if lower_actionName in CLITransformFilter.req_action_list and \
                        lower_actionName in CLITransformFilter.res_action_list:
                    req_side_needed = True
                    res_side_needed = True
                    req_side_name = actionName
                    res_side_name = "nspepi_adv_" + actionName
                elif lower_actionName in CLITransformFilter.req_action_list:
                    req_side_needed = True
                elif lower_actionName in CLITransformFilter.res_action_list:
                    res_side_needed = True
                else:
                    req_side_needed = True
                # A. Parse tree for advance command with responder feature
                if req_side_needed:
                    responder_action = CLICommand("add", "responder", "action")
                    action_name = CLIPositionalParameter(req_side_name)
                    action_type_adv = CLIPositionalParameter("respondwith")
                    responder_action.add_positional_list([
                        action_name, action_type_adv])
                    responder_action.set_upgraded()

                # B. Parse tree for advanced command with rewrite feature
                if res_side_needed:
                    rewrite_action = CLICommand("add", "rewrite", "action")
                    action_name = CLIPositionalParameter(res_side_name)
                    action_type_adv = CLIPositionalParameter("replace_http_res")
                    rewrite_action.add_positional_list([
                        action_name, action_type_adv])
                    rewrite_action.set_upgraded()

                # C. Assignment - common to both rewrite and responder
                status_code = original_cmd.positional_value(2).value
                status_list = {
                    '100': 'CONTINUE',
                    '200': 'OK',
                    '201': 'CREATED',
                    '202': 'ACCEPTED',
                    '203': 'Non-Authoritative',
                    '204': 'No Content',
                    '205': 'Reset Content',
                    '206': 'Partial Content',
                    '300': 'Multiple Choices',
                    '301': 'Moved Permanently',
                    '302': 'FOUND',
                    '303': 'See Other',
                    '304': 'Not Modified',
                    '305': 'Use Proxy',
                    '400': 'BAD REQUEST',
                    '401': 'Unauthorized',
                    '402': 'Payment Required',
                    '403': 'FORBIDDEN',
                    '404': 'Not Found',
                    '405': 'Method Not Allowed',
                    '406': 'Not Acceptable',
                    '408': 'Request Timeout',
                    '407': 'Proxy Authentication Required',
                    '409': 'Conflict',
                    '410': 'Gone',
                    '411': 'Length Required',
                    '412': 'Precondition Failed',
                    '413': 'Request Entity Too Large',
                    '414': 'Request-URI Too Long',
                    '415': 'Unsupported Media Type',
                    '500': 'INTERNAL SERVER ERROR',
                    '501': 'Not Implemented',
                    '502': 'Bad Gateway',
                    '503': 'SERVICE UNAVALIABLE',
                    '504': 'Gateway Timeout',
                    '505': 'HTTP Version Not Supported'
                    }
                if status_code not in status_list:
                    status_message = "Status " + str(status_code)
                else:
                    status_message = status_list[status_code]
                html_page = ""

                # 1. When html content/body is present in classic command:
                if original_cmd.positional_value(3):
                    html_page = original_cmd.positional_value(
                        3).value

                # Set content Length
                content_length = len(html_page)
                html_text = ' ' + status_code + ' ' + status_message \
                    + '\r\nConnection: close\r\nContent-Length: '\
                    + str(content_length) + '\r\n\r\n'\
                    + html_page
                if req_side_needed:
                    target_value = 'HTTP.REQ.VERSION.APPEND(' \
                        + responder_action.normalize(html_text) \
                        + ')'
                else:
                    target_value = 'HTTP.REQ.VERSION.APPEND(' \
                        + rewrite_action.normalize(html_text) \
                        + ')'

                target = CLIPositionalParameter(target_value)
                # A.1. Transformation to Responder feature
                if req_side_needed:
                    responder_action.add_positional(target)
                    responder_action.set_upgraded()
                    action_parse_tree_list.append(responder_action)

                # B.1. Transformation to rewrite feature
                if res_side_needed:
                    rewrite_action.add_positional(target)
                    rewrite_action.set_upgraded()
                    action_parse_tree_list.append(rewrite_action)
            elif (action_type == "drop") or (action_type == "reset"):
                """ Transformation for classicAction DROP/RESET actionType
                The action command should be removed and its actionType should
                  be used while transforming filterpolicy command.
                Example:
                add filter action act1 DROP/RESET
                Conversion Process:
                Return null for classic action command transformed.
                """
                # Save action name in a list which is used to
                # identify an action command
                return []
            elif action_type == "forward":
                """
                Conversion of FORWARD action type
                """
                action_parse_tree_list = [original_cmd]
                self._forward["action"].append(actionName)
                logging.error(
                        "Conversion of FORWARD action type related command"
                        " [{}] not supported in this tool".format(str(original_cmd).strip()))

        else:
            """
            If originial command does not have any one of the filter
            action type: ADD, ERRORCODE, DROP, RESET, CORRUPT, and FORWARD
            then log the error message
            """
            action_parse_tree_list = [original_cmd]
            logging.error(
                'Error in converting original command since' +
                ' CLI context of filter feature is invalid: ' +
                '[{}]'.format(str(original_cmd)))
        return action_parse_tree_list

    @common.register_for_cmd("add", "filter", "policy")
    def convert_filter_policy(self, policy_parse_tree):
        """
        Transform classic feature for filter policy commands
        KEY-POINTS -
           1) nspepi_adv_<actionName> stored in self._actionTypeName will
                 point to REWRITE module always
           2) Store policy name, and tuple of re[sq]Action key name, converted
                 module to help in binding time. During binding,
                 feature group and bind point are keys to focus.
        Information for variables used here:
           policyName - Name of policy
           new_policy - function to return parse tree of the converted command
           policy_action - action called by policy
           converted_pol_cmd - tree for converted input command
           dict_key - stored action type
           dict_value - stored list of action names
           action_tree - stored action command at respective index in
                 _action_command
        """
        if cli_cmds.no_conversion_collect_data:
            rule_node = policy_parse_tree.keyword_value('rule')
            expr_value = rule_node[0].value
            policy_parse_tree = CLITransformFilter.convert_keyword_expr(policy_parse_tree, 'rule')
            if policy_parse_tree.upgraded:
                expr_list = cli_cmds.get_classic_expr_list(expr_value)
                for expr_info in expr_list:
                    cli_cmds.classic_named_expr_in_use.append(expr_info[0].lower())
            if policy_parse_tree.keyword_exists("reqAction"):
                policy_action = policy_parse_tree.keyword_value(
                    "reqAction")[0].value.lower()
                CLITransformFilter.req_action_list.append(policy_action)
            else:
                policy_action = policy_parse_tree.keyword_value(
                    "resAction")[0].value.lower()
                CLITransformFilter.res_action_list.append(policy_action)
            return []
        cli_cmds.filter_policy_exists = True
        original_cmd = copy.deepcopy(policy_parse_tree)
        policyName = policy_parse_tree.positional_value(0).value
        pol_obj = common.Policy(policyName, self.__class__.__name__, "classic")
        common.pols_binds.store_policy(pol_obj)
        # Convert classic expression
        policy_parse_tree = CLITransformFilter.convert_keyword_expr(
            policy_parse_tree, 'rule')
        if not policy_parse_tree.upgraded:
            return [original_cmd]
        converted_pol_cmd, policy_action_key, orig_action_name = self.new_policy(
            policy_parse_tree, policyName)
        policy_action = orig_action_name.lower()
        if policy_action in self._htmlInjection["action"]:
            # Return input for those policies which are calling actions
            # having value as prebody or postbody Since they belong to
            # html injection family
            logging.error(
                "Conversion of HTMLInjection feature reated command [{}]"
                "not supported in this tool.".format(str(original_cmd).strip()))
            self._htmlInjection["policy"].append(policyName)
            return [original_cmd]

        if policy_action in self._forward["action"]:
            logging.error(
                "Conversion of FORWARD action type related command [{}]"
                "not supported in this tool.".format(str(original_cmd).strip()))
            self._forward["policy"].append(policyName)
            return [original_cmd]

        for dict_key, dict_value in self._actionTypeName.items():
            """ Extract key and value from stored _actionTypeName
            dictionary through action convertion """
            if policy_action not in dict_value:
                continue
            elif (dict_key == "errorcode"):
                converted_action_name = policy_action
                if policy_action in CLITransformFilter.req_action_list and \
                        policy_action in CLITransformFilter.res_action_list:
                    if (policy_action_key == "resAction"):
                        converted_action_name = "nspepi_adv_" + policy_action
                converted_pol_cmd.positional_value(2).set_value(converted_action_name)
                if (policy_action_key == "reqAction"):
                    converted_pol_cmd.group = "responder"
            elif ("nspepi_adv_" + policy_action in dict_value):
                """
                If input policy calls the action which
                should point to the action either nspepi_adv_<name> or
                original input name then below parameter should be
                changed:
                1) Group should be REWRITE for ERRORCODE for resAction
                   and RESPONDER for reqAction. REWRITE for ADD on
                   either case.
                 2) Action name should be "nspepi_adv_<name>" for
                   resAction else original name
                 3) Converted action should be taken is:
                    action of name nspepi_adv_<name> for resAction
                    else action of original name
                """
                if (policy_action_key == "resAction"):
                    converted_pol_cmd.positional_value(2) \
                        .set_value("nspepi_adv_" + policy_action)
                if (dict_key == "errorcode") and \
                   (policy_action_key == "reqAction"):
                    converted_pol_cmd.group = "responder"
                # Store converted action command first to be
                # returned in order
                action_tree = (self._action_command[policy_action][1] if (
                    policy_action_key == "resAction") else
                    self._action_command[policy_action][0])
                if action_tree not in self._policy_command:
                    # To avoid duplication
                    self._policy_command.append(action_tree)
                break
            elif (dict_key == "add") or (dict_key == "corrupt"):
                # If input policy calls one-to-one action of ADD  and
                # CORRUPT type
                break
            elif (dict_key in ["drop", "reset"]):
                # If input policy calls the custom action for drop and reset
                if (policy_action_key == "reqAction"):
                    converted_pol_cmd.group = "responder"
                policy_action = dict_key.upper()
                converted_pol_cmd.positional_value(2) \
                    .set_value(policy_action)
                break
            elif (dict_key == "forward"):
                """ If input policy calls the action which points to the action
                for FORWARD """
                logging.error(
                    "Conversion of FORWARD action type command [{}]"
                    "not supported in this tool.".format(str(original_cmd).strip()))
                return [original_cmd]

        # Changing the module name to converted module name
        pol_obj.module = self.__class__.__name__
        # Store converted tree
        self._policy_command.append(converted_pol_cmd)
        # store policy name, tuple of re[?]Action key name
        # and converted module
        if policyName not in self._converted_pol_param:
            self._converted_pol_param[policyName] = []
        self._converted_pol_param[policyName] += (
            policy_action_key, converted_pol_cmd.group, orig_action_name)
        return []

    def new_policy(self, policy_parse_tree, policyName):
        """
        This will return parse tree of the converted command
        Information for arguments used here:
            policy_parse_tree - parse tree of the command with
                                converted rule
            policyName - Name of the policy
        Information for variable used here:
            policy_action_key - re[qs]Action key used in parse tree
        """
        converted_pol_cmd = CLICommand("add", "rewrite", "policy")

        # To get the action used in policy
        if policy_parse_tree.keyword_exists("reqAction"):
            policy_action_key = "reqAction"
        if policy_parse_tree.keyword_exists("resAction"):
            policy_action_key = "resAction"
        policy_action = policy_parse_tree.keyword_value(
            policy_action_key)[0].value
        advanced_expr = policy_parse_tree.keyword_value("rule")[0].value
        policy_name = CLIPositionalParameter(policyName)
        rule = CLIPositionalParameter(advanced_expr)
        action_name = CLIPositionalParameter(policy_action)
        converted_pol_cmd.add_positional_list([
            policy_name, rule, action_name])
        converted_pol_cmd.set_upgraded()
        return converted_pol_cmd, policy_action_key, policy_action

    @common.register_for_bind(["LB", "ContentSwitching", "CacheRedirection"])
    def convert_filter_vserver_bindings(
            self, bind_parse_tree, policy_name, priority_arg, goto_arg):
        """
        Handles converted policy bindings to vservers - LB, CS, CR
        Syntax for converted policy binding:
        bind lb/cr/cs vserver <name> -policyName <string>
            [-priority <int>]
        policy_type - type of policy from convert_filter_policy
        If policy type during policy conversion is marked as
            advanced (for FORWARD and htmlInjection type) then return input
        Add -type explicitly
        """
        if cli_cmds.no_conversion_collect_data:
            return []
        policy_type = common.pols_binds.policies[policy_name].policy_type
        if policy_type == "advanced":
            # Return same if policy_type is marked advanced
            return [bind_parse_tree]

        if policy_name in self._forward["policy"]:
            logging.error(
                "Conversion of FORWARD action type related command [{}]"
                "not supported in this tool.".format(str(bind_parse_tree).strip()))
            return [bind_parse_tree]

        if policy_name in self._htmlInjection["policy"]:
            logging.error(
                "Conversion of HTMLInjection feature related command [{}]"
                "not supported in this tool.".format(str(bind_parse_tree).strip()))
            return [bind_parse_tree]

        vs_name = bind_parse_tree.positional_value(0).value.lower()
        if cli_cmds.vserver_protocol_dict[vs_name] not in ("HTTP", "SSL"):
            logging.error("Filter policy doesn't work with the non-http protocol"
                          " type vsever. And, if we bind the converted advanced"
                          " policy to the non-http vserver, then either the"
                          " config will fail or the functionality will change,"
                          " so please review and remove such config"
                          " command [{}].".format(str(bind_parse_tree).strip()))
            return ['#' + str(bind_parse_tree)]
        flow_type = ("RESPONSE" if (self._converted_pol_param[
            policy_name][0] == "resAction") else "REQUEST")
        bind_type = CLIKeywordParameter(CLIKeywordName("type"))
        bind_type.add_value(str(flow_type))
        bind_parse_tree.add_keyword(bind_type)
        bind_parse_tree.set_upgraded()
        if self._converted_pol_param[policy_name][1] == "responder":
            # Responder - Store partially converted tree separately
            self._bind_tree_resp.append(bind_parse_tree)
        else:
            # Rewrite - Store partially converted tree separately
            self._bind_tree_rw.append(bind_parse_tree)
        return []

    @common.register_for_cmd("bind", "filter", "global")
    def convert_filter_global_bindings(self, bind_parse_tree):
        """
        Handles global filter policy bindings.
        Syntax for classic policy binding:
            bind filter global <policyName> [-priority <positive_integer>]
            [-state (ENABLED | DISABLED)]
        When classic filter policy is bound:
        1. If -state is DISABLED, comment the bind command.
        2. Add -type RE[QS]_DEFAULT keyword
        3. Throw error when functionality may change.
        4. Add <goto priority> as NEXT for rewrite policy bindings and
           Add -gotoPriorityExpression as END for responder policy bindings
        """
        if cli_cmds.no_conversion_collect_data:
            return []
        orig_tree = copy.deepcopy(bind_parse_tree)
        if bind_parse_tree.keyword_exists("state") and \
                bind_parse_tree.keyword_value("state")[0].value.lower() == \
                "disabled":
            logging.warning((
                "Following bind command is commented out because"
                " state is disabled. If state is disabled, then command"
                " is not in use. Since state parameter is not supported"
                " with the advanced configuration, so if we convert this"
                " config then functionality will change. If command is"
                " required please take a backup because comments will"
                " not be saved in ns.conf after triggering 'save ns config': {}").
                format(str(bind_parse_tree).strip())
            )
            return ["#" + str(bind_parse_tree)]
        policy_name = bind_parse_tree.positional_value(0).value

        if policy_name in self._forward["policy"]:
            logging.error(
                "Conversion of FORWARD action type related command [{}]"
                "not supported in this tool.".format(str(bind_parse_tree).strip()))
            return [bind_parse_tree]

        if policy_name in self._htmlInjection["policy"]:
            logging.error(
                "Conversion of HTMLInjection feature related command [{}]"
                "not supported in this tool.".format(str(bind_parse_tree).strip()))
            return [bind_parse_tree]

        policy_type = common.pols_binds.policies[policy_name].policy_type
        if policy_type == "advanced":
            # Return input if policy_type is marked with "advanced"
            return [orig_tree]
        bind_parse_tree = CLICommand("bind", "rewrite", "global")
        bind_parse_tree.original_line = str(orig_tree)
        policyName = CLIPositionalParameter(policy_name)
        bind_parse_tree.add_positional(policyName)
        if orig_tree.keyword_exists("priority"):
            priority = CLIPositionalParameter(orig_tree.keyword_value(
                "priority")[0].value)
            bind_parse_tree.add_positional(priority)
        if self._converted_pol_param[policy_name][1] == "responder":
            """
            if converted policy is of RESPONDER module then converted bind tree
               should be of RESPONDER module else REWRITE in global binding.
            """
            bind_parse_tree.group = "responder"
        flow_type = ("RES_DEFAULT" if self._converted_pol_param[
            policy_name][0] == "resAction" else "REQ_DEFAULT")
        bind_type = CLIKeywordParameter(CLIKeywordName("type"))
        bind_type.add_value(str(flow_type))
        bind_parse_tree.add_keyword(bind_type)
        bind_parse_tree.set_upgraded()
        if bind_parse_tree.group == 'responder':
            self._bind_tree_resp.append(bind_parse_tree)
        else:
            self._bind_tree_rw.append(bind_parse_tree)
        return []

    @common.register_for_cmd("add", "filter", "htmlinjectionvariable")
    @common.register_for_cmd("set", "filter", "htmlinjectionvariable")
    @common.register_for_cmd("set", "filter", "htmlinjectionparameter")
    @common.register_for_cmd("set", "filter", "prebodyInjection")
    @common.register_for_cmd("set", "filter", "postbodyInjection")
    def convert_filter_htmlinjection_command(self, commandParseTree):
        """
        Handling Filter HTMLInjection command
        """
        if cli_cmds.no_conversion_collect_data:
            return []
        logging.error("Conversion of HTMLInjection feature"
            " related command [{}] is not supported".format(str(commandParseTree).strip()))
        return [commandParseTree]

    @common.register_for_final_call
    def get_converted_cmds(self):
        """
        Returns list of converted commands irrespective to whether
        any action used in policy
        Puts the converted command in order of first action then policy
        converted_list - Returns tree of ordered action, policy and bind
        Comment out converted bind command if existing rewrite/responder
            policies are bound with GOTO either END or USE_INVOCATION_RESULT
        """
        converted_list = []

        # If no policy but only actions are in ns.conf, then just return those
        # converted actions.
        for act_name in self._action_command:
            if (self._action_command[act_name][0] not in self._policy_command)\
               and (self._action_command[
                   act_name][1] not in self._policy_command):
                converted_list += self._action_command[act_name]
        for converted_tree in self._policy_command:
            # Ordering in a way of action first and then policy
            if converted_tree.ot == 'action':
                converted_list.insert(0, converted_tree)
            else:
                converted_list.append(converted_tree)
        # Important points for Bind command conversions:
        #   bind command of filter policies gets complicated if ns.conf already contains vserver of HTTP/S protocol type and
        #      rewrite/responder policy bindings
        #   1. If goto is END/USE_INVOCATION_RESULT exists in existing rewrite local bindings and|not global bindings
        #   2. If goto is END/USE_INVOCATION_RESULT exists in existing rewrite global bindings and|not local bindings
        #   Then comment out all partially converted rewrite global and local bindings otherwise do proper convertion
        #   Same applies for responder conditions
        rewrite_class = Rewrite()
        responder_class = Responder()
        position = "after"
        vs_name = ''
        for rw in self._bind_tree_rw:
            if rw.ot == "global":
                policy_name = rw.positional_value(0).value
                priority_arg = 1
                goto_arg = 2
            if rw.ot == "vserver":
                vs_name = rw.positional_value(0).value
                policy_name = rw.keyword_value("policyName")[0].value
                priority_arg = "priority"
                goto_arg = "gotoPriorityExpression"
            module = "Rewrite"
            cli_cmds.ConvertConfig.bind_default_goto = "NEXT"
            request_side_binding = False
            if rw.keyword_value("type")[0].value.startswith("REQ"):
                request_side_binding = True

            if ((request_side_binding and (rewrite_class.rw_req_global_goto_exists or
                 rewrite_class.rw_req_vserver_goto_exists)) or
                 ((not request_side_binding) and (rewrite_class.rw_res_global_goto_exists or
                 rewrite_class.rw_res_vserver_goto_exists))):
                bind_cmd = self.return_bind_cmd_error(rw)
                converted_list.append(bind_cmd)
            else:
                self.complete_convert_bind_cmd(
                    rw, policy_name, module, priority_arg,
                    goto_arg, position)
        for resp in self._bind_tree_resp:
            if resp.ot == "global":
                policy_name = resp.positional_value(0).value
                priority_arg = 1
                goto_arg = 2
            if resp.ot == "vserver":
                policy_name = resp.keyword_value("policyName")[0].value
                vs_name = resp.positional_value(0).value
                priority_arg = "priority"
                goto_arg = "gotoPriorityExpression"
            module = "Responder"
            cli_cmds.ConvertConfig.bind_default_goto = "END"
            if (responder_class.resp_global_goto_exists == True) or (
                 responder_class.resp_vserver_goto_exists == True):
                bind_cmd = self.return_bind_cmd_error(resp)
                converted_list.append(bind_cmd)
            else:
                self.complete_convert_bind_cmd(
                    resp, policy_name, module, priority_arg,
                    goto_arg, position)
        return converted_list

    def return_bind_cmd_error(self, cmd):
        # Return an error and partially converted commented out bind command
        logging.error("In ns.conf, existing advanced feature policies's bind commands have"
              " gotoPriorityExpression as END/USE_INVOCATION_RESULT for HTTP/S."
              " Priorities and gotoPriorityExpression will need to"
              " be added modified/added manually in [{}].".format(str(cmd).strip()))
        bind_cmd = '#' + str(cmd)
        return bind_cmd

    def complete_convert_bind_cmd(self, cmd, policy_name, module, priority_arg, goto_arg, position):
        # Pass bind command arguments to return converted bind commands
        if (cmd.ot == "global"):
            self.convert_global_bind(
                cmd, cmd, policy_name, module, priority_arg, goto_arg, position)
        if (cmd.ot == "vserver"):
            self.convert_entity_policy_bind(
                cmd, cmd, policy_name, module, priority_arg, goto_arg, position)

    def get_policy_label_name(self, vserver_name, is_req_flow_type):
        """
        Get the rewrite policy label
        vserver_name - Vserver name
        is_req_flow_type - True if the flow type is request,
                           otherwise False
        """
        suffix = ("req" if (is_req_flow_type) else "res")
        label_name = "nspepi_adv_" + vserver_name + "_" + suffix
        if len(label_name) > 127:
            if label_name not in self.overlength_policylabel_names:
                label_name, self.overlength_policylabel_counter = \
                    self.truncate_name(label_name,
                                       self.overlength_policylabel_names,
                                       self.overlength_policylabel_counter)
            else:
                label_name = self.overlength_policylabel_counter[label_name]
        return (label_name)

    def create_policy_label(self, label_name, is_req_flow_type):
        """
        Create a rewrite policylabel with the given name and flow type
        label_name - rewrite policy label name
        is_req_flow_type - True if the flow type is request,
                           otherwise False
        """
        pl_type = "http_req" if (is_req_flow_type) else "http_res"
        pl_cmd = CLICommand("add", "rewrite", "policylabel")
        name_node = CLIPositionalParameter(label_name)
        pl_type_node = CLIPositionalParameter(pl_type)
        pl_cmd.add_positional_list([name_node, pl_type_node])
        pl_cmd.set_upgraded()
        self._policylabel_name.append(label_name)
        return pl_cmd

    def bind_to_policy_label(self, label_name, policy_name):
        """
        Create a command to bind the policy to the policylabel
        label_name - rewrite policy label name
        policy_name - rewrite policy name which needs to be bound
        """
        bind_cmd = CLICommand("bind", "rewrite", "policylabel")
        name_node = CLIPositionalParameter(label_name)
        policy_node = CLIPositionalParameter(policy_name)
        new_prio = 100
        if label_name in self._policy_label_priority:
            new_prio += self._policy_label_priority[label_name]
        self._policy_label_priority[label_name] = new_prio
        prio_node = CLIPositionalParameter(str(new_prio))
        goto_node = CLIPositionalParameter("NEXT")
        bind_cmd.add_positional_list([name_node,
            policy_node, prio_node, goto_node])
        bind_cmd.set_upgraded()
        return bind_cmd

    def policy_has_add_action_type(self, policy_name):
        """
        Check whether policy is using action of ADD type
        """
        action_name = self._converted_pol_param[policy_name][2]
        if "add" in self._actionTypeName:
            return (action_name in self._actionTypeName["add"])
        else:
            return False

    def add_policy_invoke_policylabel(self, label_name, vserver_name,
            vserver_group, is_req_flow_type):
        """
        Create a rewrite policy and bind it globally to the invoke
        the policylabel
        label_name - rewrite policy label name
        vserver_name - vserver name in which filter policy is bound
        vserver_group - vserver group: lb, cs or cr
        is_req_flow_type - True if binding is for request side,
                           otherwise False
        """
        method_name = "LB" if (vserver_group == "lb") else "CS"
        rule_expr = '((HTTP.REQ.' + method_name + '_VSERVER.NAME ALT "").EQ("' + vserver_name + '"))'

        pol_cmd = CLICommand("add", "rewrite", "policy")

        policy_name = "nspepi_rw_" + vserver_name + "_pol"
        if len(policy_name) > 127:
            if policy_name not in self.overlength_policy_names:
                policy_name, self.overlength_policy_counter = \
                    self.truncate_name(policy_name,
                                       self.overlength_policy_names,
                                       self.overlength_policy_counter)
            else:
                policy_name = self.overlength_policy_names[policy_name]
        policy_node = CLIPositionalParameter(policy_name)
        rule_node = CLIPositionalParameter(rule_expr)
        action_node = CLIPositionalParameter("NOREWRITE")
        pol_cmd.add_positional_list([policy_node, rule_node, action_node])
        pol_cmd.set_upgraded()

        bind_cmd = CLICommand("bind", "rewrite", "global")
        policy_node = CLIPositionalParameter(policy_name)
        prio_node = CLIPositionalParameter("100")
        goto_node = CLIPositionalParameter("NEXT")
        bind_cmd.add_positional_list([
            policy_node, prio_node, goto_node])
        type_node = CLIKeywordParameter(CLIKeywordName("type"))
        type_node.add_value("REQ_OVERRIDE" if (is_req_flow_type) else "RES_OVERRIDE")
        bind_cmd.add_keyword(type_node)
        invoke_node = CLIKeywordParameter(CLIKeywordName("invoke"))
        invoke_node.add_value_list(["policylabel", label_name])
        bind_cmd.add_keyword(invoke_node)
        self.complete_convert_bind_cmd(bind_cmd,
            policy_name, "rewrite", 1, 2, "before")

        return pol_cmd

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

    def modify_global_binding(self, parse_tree, is_req_flow_type):
        """
        Modify the current bindig and bind it to the RE[Q\S]_OVERRIDE
        with gotoPriorityExpression NEXT.
        parse_tree - Parse tree of the current binding
        is_req_flow_type - True if binding is for request side,
                           otherwise False
        """
        bind_cmd = CLICommand("bind", "rewrite", "global")
        policy_name = parse_tree.positional_value(0).value
        policy_node = CLIPositionalParameter(policy_name)
        prio_node = CLIPositionalParameter("100")
        goto_node = CLIPositionalParameter("NEXT")
        bind_cmd.add_positional_list([
            policy_node, prio_node, goto_node])
        type_node = CLIKeywordParameter(CLIKeywordName("type"))
        type_node.add_value("REQ_OVERRIDE" if (is_req_flow_type) else "RES_OVERRIDE")
        bind_cmd.add_keyword(type_node)
        self.complete_convert_bind_cmd(bind_cmd,
            policy_name, "rewrite", 1, 2, "before")

