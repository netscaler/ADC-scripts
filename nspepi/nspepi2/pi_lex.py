#!/usr/bin/env python2

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import logging
import re


class PILex(object):
    """
    Class to parse PI expressions.
    """

    @staticmethod
    def get_pi_string(expr):
        """
        Helper function to get classic expression from
        SYS.EVAL_CLASSIC_EXPR("<>").
        expr - should be substring which starts from opening quote in
        SYS.EVAL_CLASSIC_EXPR expression to the end of string.
        Example:
            "ns_true") && true - Returns ns_true
        Return values:
            -classic expression after removing quotes and handling backslashes
            -length of classic expression including double quotes in original
             expression expr.
        """
        if not expr.startswith('"'):
            return None
        index = 0
        value = ""
        # Increment by 1 for opening quote
        index += 1
        expr_length = len(expr)
        while index < expr_length:
            if expr[index] == '\\':
                index += 1
                if index >= expr_length:
                    return None
                if expr[index] in '\\\'"':
                    value += expr[index]
                elif expr[index] == 't':
                    value += '\t'
                elif expr[index] == 'r':
                    value += '\r'
                elif expr[index] == 'n':
                    value += '\n'
                elif expr[index] == 'x':
                    # Taking next 2 characters to validate for hex digits and
                    # then to convert to byte.
                    # Now index points to 2nd hex digit
                    index += 2
                    if (index < expr_length and re.match(r"^[0-9a-fA-F]{2}$",
                       expr[index - 1: index + 1])):
                        hex_digits = expr[index - 1: index + 1]
                        hex_digits = int(hex_digits, 16)
                        if hex_digits > 127:
                            logging.error("Invalid hex value is used. Maximum "
                                          "hex value allowed is 7f.")
                            return None
                        value += chr(hex_digits)
                    else:
                        return None
                elif expr[index] in "01234567":
                    # Check for oct digits and convert to byte.
                    m = re.match(r"^([0-7]{1,3})", expr[index:])
                    oct_digits = m.group(1)
                    oct_digits_length = len(oct_digits)
                    # Now index points to last octal digit.
                    index += oct_digits_length - 1
                    oct_digits = int(oct_digits, 8)
                    if oct_digits > 127:
                        logging.error("Invalid octal value is used. Maximum "
                                      "octal value allowed is 177.")
                        return None
                    value += chr(oct_digits)
                else:
                    return None
            elif expr[index] == '"':
                break
            else:
                value = value + expr[index]
            index += 1
        if index >= expr_length:
            return None
        # Increment by 1 for closing quote.
        value_length = index + 1
        return [value, value_length]
