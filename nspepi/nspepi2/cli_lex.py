#!/usr/bin/env python

# Copyright 2021 Citrix Systems, Inc.  All rights reserved.
# Use of this software is governed by the license terms, if any,
# which accompany or are included with this software.

"""
  CLI lexical analyzer.
"""

import logging


class LexToken(object):
    """
    Class to represent the token.
    Instance variables:
            type   - Token type
            value  - Token value
            lineno - line number where the
                        token value is in the data parsed
            lexpos - Points to the token end position
    """

    def __init__(self, token_type, token_value, lineno, lex_pos):
        self.type = token_type
        self.value = token_value
        self.lineno = lineno
        self.lexpos = lex_pos

    def __str__(self):
        return self.value

    def __repr__(self):
        return "LexToken({},{},{},{})".format(
            self.type,
            self.value,
            self.lineno,
            self.lexpos
        )


class Lexer(object):
    """
    CLI lexical analyzer.
    Instance variables:
            data           - data to be parsed
            lex_pos        - Points to the current position during parsing
            length         - length of the remaining data that
                             has to be parsed
            token_value    - value of the current token during tokenization
    """

    def __init__(self):
        self._data = None
        self._lex_pos = 0
        self._length = 0
        self._token_value = ""

    def input(self, command):
        """
        Sets the lexical analyzer with the data that has to be parsed.
        command - command that has to be parsed
        """
        self._data = command
        self._lex_pos = 0
        self._length = len(self._data)
        self._token_value = ""

    def token(self):
        """
        Returns next token in a CLI command as a LexToken object.
        If there is no more data to be parsed, returns None.
        """
        start_pos = self._lex_pos

        # Handling spaces that comes around the tokens
        while self._length > 0 and (self._data[self._lex_pos] in " \t\n"):
            self.advance_token()

        # Ignoring comments
        if self._length > 0 and self._data[self._lex_pos] == '#':
            self.advance_token(self._length)

        # When there is no more input to be parsed, returns None
        if self._length <= 0:
            return None

        # Identifies Token type
        token_type = None
        if self._data[self._lex_pos] == '-':
            token_type = "KEY_ARG"
            # Removing '-' from the starting of the keyword
            self.advance_token()

            # quotes are not allowed in keywords
            self._token_value = ""
            while self._length > 0:
                if self._data[self._lex_pos] in " \t\n":
                    return LexToken(token_type, self._token_value, 1,
                                    self._lex_pos - 1)
                else:
                    self.advance_and_append_token(self._data[self._lex_pos])
            return LexToken(token_type, self._token_value, 1,
                            self._lex_pos - 1)
        else:
            token_type = "NON_KEY"

        start_pos = self._lex_pos

        # Handling q quote
        qquote_start_delims = "/{<|~$^+=&%@`?"
        qquote_end_delims = {"{": "}", "<": ">"}

        if (self._length > 2 and self._data[start_pos] == 'q' and
           self._data[start_pos + 1] in qquote_start_delims):
            qquote_end_char = qquote_end_delims.get(self._data[start_pos + 1],
                                                    self._data[start_pos + 1])
            qquote_end_index = self._data.find(qquote_end_char, start_pos + 2)
            if (qquote_end_index != -1 and
                (qquote_end_index == len(self._data) - 1 or
                 self._data[qquote_end_index + 1] in " \t\n")):
                next_token = LexToken("NON_KEY",
                                      self._data[start_pos + 2:
                                                 qquote_end_index],
                                      1, qquote_end_index)
                self.advance_token(len(next_token.value) + 3)
                return next_token

        state = " "
        parenthesis_counter = 0
        self._token_value = ""
        while self._length > 0:
            if self._data[self._lex_pos] in "\"'":
                if self._data[self._lex_pos] == state:
                    # end of quotes
                    state = " "
                    """
                    If token starts with quotes and the corresponding ending
                        quotes appear, then this will be the end of the token.
                    If token doesn't start with the quote,
                        then this will be the end of the quote but not the
                        end of the token.
                    """
                    if self._data[self._lex_pos] == self._data[start_pos]:
                        # Removing end quotes by not appending the character
                        self.advance_token()
                        break
                    self.advance_and_append_token(self._data[self._lex_pos])
                elif state in "\"'":
                    # single quote within double quote or vice versa
                    self.advance_and_append_token(self._data[self._lex_pos])
                else:
                    # now inside quotes
                    state = self._data[self._lex_pos]
                    # Removing starting quotes
                    if self._lex_pos != start_pos:
                        self.advance_and_append_token(
                                        self._data[self._lex_pos])
                    else:
                        self.advance_token()
            elif self._data[self._lex_pos] in " \t\n":
                if state == " " and parenthesis_counter == 0:
                    break
                # This case occurs when whitespace appears inside quotes
                self.advance_and_append_token(self._data[self._lex_pos])
            elif self._data[self._lex_pos] == "(":
                self.advance_and_append_token(self._data[self._lex_pos])
                if state not in "\"'":
                    parenthesis_counter += 1
            elif self._data[self._lex_pos] == ")":
                self.advance_and_append_token(self._data[self._lex_pos])
                if state not in "\"'":
                    if parenthesis_counter > 0:
                        parenthesis_counter -= 1
                    else:
                        self.advance_token(self._length)
                        token_type = "ERROR"
                        logging.error("Unbalanced closed parenthesis : [{}]".format(self._data))
                        break
            elif self._data[self._lex_pos] == "\\":
                # backslashes are escapes inside quotes
                if state in "\"'":
                    if self._length == 1:
                        # \\ followed by end of the command
                        self.advance_and_append_token(
                                        self._data[self._lex_pos])
                        token_type = "ERROR"
                        logging.error("Blackslashes inside quotes are followed by end of the command : [{}]".format(self._data))
                        break
                    if self._data[self._lex_pos + 1] == 't':
                        self.advance_and_append_token('\t', 2)
                    elif self._data[self._lex_pos + 1] == 'n':
                        self.advance_and_append_token('\n', 2)
                    elif self._data[self._lex_pos + 1] == 'r':
                        self.advance_and_append_token('\r', 2)
                    elif self._data[self._lex_pos + 1] in "'\"\\":
                        self.advance_and_append_token(
                                        self._data[self._lex_pos + 1], 2)
                    else:
                        self.advance_and_append_token(
                                        self._data[self._lex_pos])
                else:
                    self.advance_and_append_token(self._data[self._lex_pos])
            else:
                self.advance_and_append_token(self._data[self._lex_pos])

        if state in "\"'" or parenthesis_counter > 0:
            # error token for not matching with any rule
            token_type = "ERROR"
            logging.error("Unbalanced parenthesis or quotes : [{}]".format(self._data))
        next_token = LexToken(token_type, self._token_value, 1,
                              self._lex_pos - 1)
        return next_token

    def advance_token(self, number=1):
        """
        This function increments the class instance variable lex_pos and
        decrements the length variable by the number that is passed as
        argument.
        number - number by which the increment has to be done
        """
        self._lex_pos += number
        self._length -= number

    def advance_and_append_token(self, token_char, number=1):
        """
        This function advances current position by the number that is
        passed as argument and appends the token value based on token_char.
        number     - number by which current position is incremented,
                     by default it is 1
        token_char - character that has to be appened to the token value
        """
        self.advance_token(number)
        self._token_value += token_char

    @staticmethod
    def adv_ident_char(ch):
        """ Helper function to check whether
            character is an Advanced identifier character:
            letter, underscore, or digit.
            ch - character to check
        """
        return (ch == "_") or ch.isdigit() or ch.isalpha()

    def adv_expr_token(self):
        """
        This function is used to tokenize an Advanced
        expression.
        Note that currently this only recognizes a subset of the token types.
        Returns next token as LexToken object.
        If there is no more data to be parsed, returns None.
        """
        # Handling spaces that comes around the tokens
        while self._length > 0 and (self._data[self._lex_pos] in " \t\r\n"):
            self.advance_token()

        # When there is no more input to be parsed, returns None
        if self._length <= 0:
            return None

        # Identifies Token type
        token_type = "OTHER"

        start_pos = self._lex_pos

        state = " "
        self._token_value = ""
        while self._length > 0:
            if state == "REGEX" and self._data[self._lex_pos] == regex_end:
                # End of regex
                state = " "
                self.advance_token()
                break
            elif self._data[self._lex_pos] in "\"'":
                if self._data[self._lex_pos] == state:
                    # end of quotes
                    state = " "
                    # Removing end quotes by not appending the character
                    self.advance_token()
                    break
                elif state in "\"'":
                    # single quote within double quote or vice versa
                    self.advance_and_append_token(self._data[self._lex_pos])
                elif state == "REGEX":
                    self.advance_and_append_token(self._data[self._lex_pos])
                else:
                    # now inside quotes
                    state = self._data[self._lex_pos]
                    # Removing starting quotes
                    self.advance_token()
                    token_type = "STRING"
            elif state == " " and self._data[self._lex_pos] in " \t\r\n":
                # Whitespace ends most tokens
                break
            elif (state == " " and self._length >= 5 and
                    self._data[self._lex_pos:self._lex_pos+2].lower() == 're'
                    and not Lexer.adv_ident_char(self._data[self._lex_pos+2])):
                # Start of regex
                state = "REGEX"
                token_type = "REGEX"
                regex_end = self._data[self._lex_pos+2]
                self.advance_token(3)
            elif ((self._data[self._lex_pos] == "_") or
                  (self._data[self._lex_pos].isalpha())):
                if ((state not in "\"'" and state != "IDENTIFIER" and
                     state != "REGEX" and self._lex_pos != start_pos)):
                    # End of "other"
                    break
                elif state not in "\"'" and state != "REGEX":
                    # start of an identifier
                    state = "IDENTIFIER"
                    token_type = "IDENTIFIER"
                    self.advance_and_append_token(self._data[self._lex_pos])
                else:
                    self.advance_and_append_token(self._data[self._lex_pos])
            elif (not Lexer.adv_ident_char(self._data[self._lex_pos])):
                if state == "IDENTIFIER":
                    state = " "
                    break
                else:
                    # More of identifier
                    self.advance_and_append_token(self._data[self._lex_pos])
            elif self._data[self._lex_pos] == "\\":
                # backslashes are escapes inside quotes
                if state in "\"'":
                    if self._length == 1:
                        # \\ followed by end of the expression
                        self.advance_and_append_token(
                                        self._data[self._lex_pos])
                        token_type = "ERROR"
                        logging.error("Blackslashes inside quotes are followed by end of the expression : [{}]".format(self._data))
                        break
                    if self._data[self._lex_pos + 1] == 't':
                        self.advance_and_append_token('\t', 2)
                    elif self._data[self._lex_pos + 1] == 'n':
                        self.advance_and_append_token('\n', 2)
                    elif self._data[self._lex_pos + 1] == 'r':
                        self.advance_and_append_token('\r', 2)
                    elif self._data[self._lex_pos + 1] in "'\"\\":
                        self.advance_and_append_token(
                                        self._data[self._lex_pos + 1], 2)
                    else:
                        self.advance_and_append_token(
                                        self._data[self._lex_pos])
                else:
                    self.advance_and_append_token(self._data[self._lex_pos])
            else:
                self.advance_and_append_token(self._data[self._lex_pos])

        if state in "\"'":
            # error token for not matching with any rule
            token_type = "ERROR"
            logging.error("Unbalanced quotes : [{}]".format(self._data))
        elif state == "REGEX":
            # error token for not matching with any rule
            token_type = "ERROR"
            logging.error("Unterminated regex : [{}]".format(self._data))
        next_token = LexToken(token_type, self._token_value, 1,
                              self._lex_pos - 1)
        return next_token
