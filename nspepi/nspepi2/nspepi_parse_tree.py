#!/usr/bin/env python2

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

import re
import logging
from collections import OrderedDict

import nspepi_common as common


"""
Parse tree implementation

Example:
Assume you had the command at line 123:
    add responder action foo respondwith "HTTP/1.1 403 Forbidden\r\n\r\n" -comment "My comment"
then you would get the following parse tree (note: when generating a new parse
tree that is a replacement for something in ns.conf you can just pass '' for
the original text):

CLICommand ('add', 'responder', 'action')
      |
    CLIPositionalParameter ('foo')
      |
    CLIPositionalParameter ('respondwith')
      |
    CLIPositionalParameter ('"HTTP/1.1 403 Forbidden\r\n\r\n"')
      |
    CLIKeywordParameter
            |
        CLIKeywordName ('comment') [note no '-']
            |
        CLIKeywordValue ('My comment')

This tree can be created by the following code:
    cmd = CLICommand('add', 'responder', 'action')
    # Note the 'quoted' parameter is defaulted to False below
    pp = CLIPositionalParameter('foo')
    cmd.add_positional(pp)
    pp = CLIPositionalParameter('respondwith')
    cmd.add_positional(pp)
    pp = CLIPositionalParameter(r'"HTTP/1.1 403 Forbidden\r\n\r\n"')
    cmd.add_positional(pp)
    kwn = CLIKeywordName('comment')
    kwp = CLIKeywordParameter(kwn)
    # Note the 'quoted' parameter to CLIKeywordValue is defaulted to False
    kwp.add_value('My comment')
    cmd.add_keyword(kwp)
"""


class CLIParseTreeNode(object):
    """ A CLI parse tree node """
    must_quote_chars = re.compile('[ \t\r\n"\'\\\\()]')
    must_escape_chars = "\t\r\n\"\\"
    qquote_delims = "/{<|~$^+=&%@`?"

    def __init__(self):
        """ Create a CLI parse tree node object """
        pass

    def normalize(self, val, make_str=False):
        """ Normalizes the string representation for an item in a CLI command
            so that it will correctly be understood by the CLI.
        val - the string value to normalize.
        make_str - to normalize when special characters are needed in string.
        Returns the normalized string.
        """
        # Only uses double quotes if any quoting is needed.
        # This may put in quotes in some cases where they are not actually
        # needed.
        result = val
        str_len = len(val)
        if str_len == 0:
            result = '""'
        else:
            if (make_str or val[0] == '-' or val[0] == '#'
                    or (val[0] == 'q' and str_len > 1 and
                        val[1] in self.qquote_delims)
                    or self.must_quote_chars.search(val)):
                result = '"'
                for ch in val:
                    if ch in self.must_escape_chars:
                        if ch == '\t':
                            result += '\\t'
                        elif ch == '\r':
                            result += '\\r'
                        elif ch == '\n':
                            result += '\\n'
                        else:
                            result += '\\' + ch
                    else:
                        result += ch
                result += '"'
        return result


class CLICommand(CLIParseTreeNode):
    """ A CLI configuration command """

    def __init__(self, op, group, ot):
        """ Create a CLI command object
        upgraded - Indicates whether the command is upgraded or not
        adv_upgraded - In many places of the code, upgraded flag is used to determine if original policy is classic
                       or advanced. If upgraded is true, then original policy is considered to be classic. But advanced
                       policies can have SYS.EVAL_CLASSIC_EXPR, which needs to be converted as well. Here original
                       policy is advanced but need to set upgrade flag after conversion. adv_upgraded should be used
                       in such cases instead of upgraded.
        invalid - Indicates whether the command is invalid in 13.1 release.
        original_line - the text of the line that was parsed
        lineno - the line number (starting with 1) that the command occurs on
        op - the op-code for the command
        group - the group for the command
        ot - the object type
        """
        self._upgraded = True
        self._adv_upgraded = True
        self._invalid = False
        self._original_line = ""
        self._lineno = 0
        self._op = op
        self._group = group
        self._ot = ot
        self._positionals = []
        self._keywords = OrderedDict()
        super(CLICommand, self).__init__()
        logging.debug('CLICommand created: op=' + op +
                      ', group=' + group +
                      ', ot=' + ot)

    def get_command_type(self):
        return [self._op, self._group, self._ot]

    @property
    def lineno(self):
        return self._lineno

    @lineno.setter
    def lineno(self, lineno):
        self._lineno = lineno
        logging.debug('CLICommand lineno set: ' + str(lineno))

    @property
    def original_line(self):
        return self._original_line

    @original_line.setter
    def original_line(self, original_line):
        self._original_line = original_line
        self._upgraded = False
        self._adv_upgraded = False
        logging.debug('CLICommand original_line set: ' + original_line +
                      ', upgraded set to False')

    @property
    def op(self):
        return self._op

    @op.setter
    def op(self, op):
        self._op = op
        logging.debug('CLICommand ot set: ' + op)

    @property
    def group(self):
        return self._group

    @group.setter
    def group(self, group):
        self._group = group
        logging.debug('CLICommand ot set: ' + group)

    @property
    def ot(self):
        return self._ot

    @ot.setter
    def ot(self, ot):
        self._ot = ot
        logging.debug('CLICommand ot set: ' + ot)

    def set_upgraded(self):
        """ Flags that this command was upgraded. """
        self._upgraded = True
        logging.debug('CLICommand upgraded flag set')

    @property
    def upgraded(self):
        return self._upgraded

    def set_adv_upgraded(self):
        """ Flags that this advanced command was upgraded. """
        self._adv_upgraded = True
        logging.debug('CLICommand adv_upgraded flag set')

    @property
    def adv_upgraded(self):
        return self._adv_upgraded

    def set_invalid(self):
        """ Flags that this command is invalid. """
        self._invalid = True
        logging.debug('CLICommand invalid flag set')

    @property
    def invalid(self):
        return self._invalid

    def add_positional(self, positional_param):
        """ Adds a positional parameter at the end of the parameters.
        positional_param - the node containing the value of the parameter
        """
        assert isinstance(positional_param, CLIPositionalParameter)
        self._positionals.append(positional_param)
        logging.debug('CLICommand positional parameter added: ' +
                      str(positional_param))

    def add_positional_list(self, positional_params):
        """ Adds a list of positional parameters.
        positional_params - a list of nodes containing the parameter values
        """
        for pos in positional_params:
            assert isinstance(pos, CLIPositionalParameter)
            self._positionals.append(pos)
            logging.debug('CLICommand positional parameter added: ' +
                          str(pos))

    def remove_positional(self, inx):
        """ Removes the given positional parameter.
        NOTE: once a positional parameter is removed the following
        positional parameters' indexes are decremented by 1.
        inx - the (zero-based) index of the positional parameter.
        """
        assert inx < len(self._positionals) and inx >= 0
        del self._positionals[inx]
        self._upgraded = True
        logging.debug('CLICommand positional parameter removed at index: ' +
                      str(inx))

    def add_keyword(self, keyword_param):
        """ Adds a keyword parameter at the end of the parameters.
        keyword_param - the keyword parameter node to add
        """
        assert isinstance(keyword_param, CLIKeywordParameter)
        self._keywords[keyword_param.name.name] = keyword_param
        logging.debug('CLICommand keyword parameter added: ' +
                      str(keyword_param))

    def add_keyword_list(self, keyword_params):
        """ Adds a list of keyword parameters.
        keyword_params - a list of keyword parameter nodes to add
        """
        for kw in keyword_params:
            assert isinstance(kw, CLIKeywordParameter)
            self._keywords[kw.name.name] = kw
            logging.debug('CLICommand keyword parameter added: ' +
                          str(kw))

    def remove_keyword(self, name):
        """ Removes the given keyword parameter.
        name - the name of the keyword (without the "-")
        """
        assert name in self._keywords
        del self._keywords[name]
        self._upgraded = True
        logging.debug('CLICommand keyword parameter removed with key: ' +
                      str(name))

    def remove_keyword_value(self, name, inx):
        """ Some keywords will have multiple values.
        This method removes a particular keyword value given by index
        inx in given keyword.
        name - the name of the keyword (without the "-")
        inx - the (zero-based) index of the keyword value.
        NOTE: once a keyword value is removed the following keyword values
        indexes are decremented by 1.
        """
        assert name in self._keywords
        keyword_param = self._keywords[name]
        assert inx < len(keyword_param.values) and inx >= 0
        del keyword_param.values[inx]
        self._upgraded = True
        logging.debug('CLICommand keyword parameter value removed at index: ' +
                      str(inx) + " with key: " + str(name))

    def keyword_exists(self, name):
        """ Determine whether the given keyword existins for this command.
        name - the name of the keyword (without the "-")
        Returns true iff the keyword exists for this command.
        """
        return name in self._keywords

    def keyword_parameter(self, name):
        """ Gets the keyword parameter for the given keyword.
        name - the name of the keyword (without the "-")
        Returns the parameter or None if the keyword does not exist in this
            command.
        """
        return self._keywords.get(name)

    def keyword_value(self, name):
        """ Gets the keyword value for the given keyword.
        name - the name of the keyword (without the "-")
        Returns the value or None if the keyword does not exist in this
            command.
        """
        result = self._keywords.get(name)
        if result is not None:
            result = result.values
        return result

    def positional_value(self, inx):
        """ Gets the given positional parameter.
        inx - the (zero-based) index of the positional parameter.
        Returns the value or None if no such positional parameter exists.
        """
        result = None
        if inx < len(self._positionals) and inx >= 0:
            result = self._positionals[inx]
        return result

    def get_number_of_params(self):
        """ Gets the number of parameters. """
        no_of_params = len(self._positionals) + len(self._keywords)
        return no_of_params

    def __str__(self):
        """ Creates a readable string representation of the CLI node.
        Returns the string representation.
        """
        if not (self._upgraded or self._adv_upgraded):
            return self._original_line
        else:
            result = self._op + " " + self._group + " " + self._ot
            for node in self._positionals:
                result += " " + str(node)
            for node in self._keywords.values():
                result += " " + str(node)
            return result + "\n"

    def __repr__(self):
        """ Creates an unambiguous representation of the CLI node.
        Returns the string representation.
        """
        return common.class_repr(self)


class CLIPositionalParameter(CLIParseTreeNode):
    """ A CLI positional parameter """

    def __init__(self, value):
        """ Creates a positional node.
        value - the value of the parameter
        """
        self._value = value
        self._quoted = False
        super(CLIPositionalParameter, self).__init__()
        logging.debug('CLIPositionalParameter created: value=' + str(value))

    @property
    def value(self):
        return self._value

    @property
    def quoted(self):
        return self._quoted

    @quoted.setter
    def quoted(self, quoted):
        self._quoted = quoted

    def set_value(self, value, quoted=False):
        """ Set the value of this parameter.
        value - the value to set
        quoted - true if the value is in properly quoted output format
        """
        self._value = value
        self._quoted = quoted
        logging.debug('CLIPositionalValue value updated: value=' + str(value)
                      + ', quoted=' + str(quoted))

    def __str__(self):
        """ Creates a readable string representation of the positional
        parameter.
        Returns the string representation.
        """
        if self._quoted:
            return self._value
        else:
            return self.normalize(self._value)

    def __repr__(self):
        """ Creates an unambiguous representation of the positional parameter.
        Returns the string representation.
        """
        return common.class_repr(self)


class CLIKeywordParameter(CLIParseTreeNode):
    """ A CLI keyword parameter """

    def __init__(self, name):
        """ Creates a keyword parameter, initialized to have no value.
        name - the keyword name node
        """
        assert isinstance(name, CLIKeywordName)
        self._name = name
        self._values = []
        super(CLIKeywordParameter, self).__init__()
        logging.debug('CLIKeywordParameter created: name=' + str(name))

    def add_value(self, value):
        """ Adds a value to the end of the list of keyword values.
        value - the keyword value node to add
        """
        child = CLIKeywordValue(value)
        self._values.append(child)
        logging.debug('CLIKeywordParameter value added: ' + str(value))

    def add_value_list(self, values):
        """ Adds a list of keyword values.
        values - a list of keyword values
        """
        for val in values:
            self.add_value(val)

    def __str__(self):
        """ Creates a readable string representation of the keyword parameter
        node.
        Returns the string representation.
        """
        result = str(self._name)
        for value in self._values:
            result += " " + str(value)
        return result

    def __repr__(self):
        """ Creates an unambiguous representation of the keyword parameter.
        Returns the string representation.
        """
        return common.class_repr(self)

    @property
    def name(self):
        """ Gets the keyword name node.
        Returns the keyword name node.
        """
        return self._name

    @property
    def values(self):
        """ Gets the keyword value nodes.
        Returns the list of keyword value nodes.
        """
        return self._values


class CLIKeywordName(CLIParseTreeNode):
    """ A CLI keyword name """

    def __init__(self, name):
        """ Creates a keyword name node.
        name - the name of the keyword (without the "-")
        """
        self._name = name
        super(CLIKeywordName, self).__init__()
        logging.debug('CLIKeywordName created: name=' + name)

    @property
    def name(self):
        """ Gets the keyword name.
        Returns the keyword name.
        """
        return self._name

    def __str__(self):
        """ Creates a readable string representation of the keyword name node.
        Returns the string representation.
        """
        return "-" + self._name

    def __repr__(self):
        """ Creates an unambiguous representation of the keyword name node.
        Returns the string representation.
        """
        return common.class_repr(self)


class CLIKeywordValue(CLIParseTreeNode):
    """ The value for a CLI keyword parameter """

    def __init__(self, value):
        """ Creates a keyword value node.
        value - a value for the keyword.
        """
        self._value = value
        self._quoted = False
        super(CLIKeywordValue, self).__init__()
        logging.debug('CLIKeywordValue created: value=' + str(value))

    @property
    def value(self):
        return self._value

    @property
    def quoted(self):
        return self._quoted

    @quoted.setter
    def quoted(self, quoted):
        self._quoted = quoted

    def set_value(self, value, quoted=False):
        """ Set the value of this parameter.
        value - the value to set
        quoted - true if the value is in properly quoted output format
        """
        self._value = value
        self._quoted = quoted
        logging.debug('CLIKeywordValue value updated: value=' + str(value) +
                      ', quoted=' + str(quoted))

    def __str__(self):
        """ Creates a readable string representation of the keyword value node.
        Returns the string representation.
        """
        if self._quoted:
            return self._value
        else:
            return self.normalize(self._value)

    def __repr__(self):
        """ Creates an unambiguous representation of the keyword value node.
        Returns the string representation.
        """
        return common.class_repr(self)
