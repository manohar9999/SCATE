#!/bin/env python

################################################################################
#
# file : Tool.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

from .DataAbstractions import ResultSet, Weakness, Suite, Flaw, FlawType, Bug
from . import Utilities

import logging
import os
import re

#
# Base class for Tools - To build and analyse
#
class Tool:
  #
  # Initializing constructor
  #
  # @param[in]        name          Name of the tool
  # @param[in]        mapping       CWE mapping for tool
  #
  def __init__ (self, name, mapping):
    self.__name__ = name
    self.__weakness_map__ = mapping
    self.__cwe_matcher__ = re.compile ('(?P<cwe>CWE[0-9]*)')

  #
  # Get the name of the tool
  #
  def name (self):
    return self.__name__

  #
  # Get the string representation of the tool.
  #
  def __repr__(self):
    return self.__name__

  #
  # Test if the bug was identified by the correct checker. This means
  # that the bug type must be classified under the correct weakness.
  #
  def correct_checker (self, bug, weakness):
    index = weakness.find ('_');

    if index == -1:
      cwe = weakness
    else:
      cwe = weakness[:index]

    return (cwe in self.__weakness_map__) and (bug.type in self.__weakness_map__[cwe])

  # {@ Report hooks

  #
  # Determine if the tool supports reporting on the provided granularity
  #
  def supports_granularity (self, granularity):
    return True

  #
  # Determine if the tool supports a specific weakness
  #
  def supports_weakness (self, weakness):
    # We have to use a regular expression matcher to determine if the weakness
    # is supported. This is because some of the test suites add more than just
    # the weakness name to the weakness. We therefore only need to make sure the
    # weakness is encoded somewhere in the original weakness name.
    logging.debug ('checking if [%s] supports [%s]' % (self.__name__, weakness.name))
    result = self.__cwe_matcher__.match (weakness.name)

    if not result:
      return False

    cweName = result.group ('cwe')
    return cweName in self.__weakness_map__

  # @}

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    pass

  #
  # Initialize the tool
  #
  def parse_args (self, args):
    self.__threads__ = args.threads
    self.__SCATE_root__ = os.path.realpath (os.path.join (os.path.dirname (__file__), '../../'))

    if args.weaknesses:
      self.__weaknesses__ = args.weaknesses.split (',')
    else:
      self.__weaknesses__ = None

  # {@ Build hooks

  #
  # Create the result set to use for a build
  #
  def build_result_set (self):
    return ResultSet ('resultset', self.__name__)

  #
  # Handle cleaning a suite
  #
  def handle_clean (self, suite):
    pass

  #
  # Handle compiling a suite
  #
  def handle_compile (self, suite):
    pass

  #
  # Handle generating the build document for a suite
  #
  def handle_docgen (self, suite):
    pass

  # @}
