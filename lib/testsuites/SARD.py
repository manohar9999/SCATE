#!/bin/env python

from ..ImportSuite import ImportSuite
from ..DataAbstractions import *

import os
import logging

from lxml import objectify

#
# Factory method that creates the CppCheck tool
#
def __create__ ():
  return SARD ()

#
# @class SARD
#
class SARD (ImportSuite):
  #
  # Initializing constructor.
  #
  def __init__ (self):
    super (SARD, self).__init__ ('SARD')

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    super (SARD, self).init_parser (parser)

    testSuiteParser = parser.add_parser (self.getSource(), help='use %s test suite' % self.getSource())
    testSuiteParser.set_defaults (suite=self)

  #
  # Main entry point for import commands.  This should result in
  # populating the result set.
  #
  def import_testcases (self, result_set):
    logging.info ('searching for test case manifest')

    # Locate the manifest files that lists all the test cases.
    manifest = [f for f in os.listdir (self.__basepath__)
                if os.path.isfile (os.path.join (self.__basepath__, f)) and f.startswith ('manifest')]
    length = len (manifest)

    testcases = os.path.join (self.__basepath__, 'testcases')

    if length == 0:
      logging.error ('directory does not contain manifest')
    elif length == 1:
      filename = os.path.join (self.__basepath__, manifest[0])
      root = objectify.parse (filename).getroot ();

      for testcase in root.iter ('testcase'):
        id = testcase.get ('id')

        for file_element in testcase.iter ('file'):
          path = file_element.get ('path')

          for flaw_element in file_element.iter ('flaw'):
            name_element = flaw_element.get ('name')
            line_element = flaw_element.get ('line')

            # Extract the CWE from the name of the flaw.
            name_and_description = name_element.split (':')
            name_tokens = name_and_description[0].split ('-')
            cwe = ''.join (name_tokens)

            description = name_and_description[1].strip ()

            # Add the flaw to the result set.
            weakness = result_set.get_weakness (cwe)
            suite_id = os.path.join (self.__basepath__, 'testcases', os.path.dirname (path))
            filename = os.path.basename (path)

            suite = weakness.get_suite (suite_id, 'make', 'all')
            file = suite.get_file (filename)
            function = file.get_function ('Unknown')
            line = function.get_line (int (line_element))
            line.add_flaw (FlawType.Flaw, description, 'SARD')

    else:
      logging.error ('Multiple manifest is not supported')

    return result_set

  #
  # Default elements passed when ParseAction is called are st,locn,toks
  #
  def printloc (self, st, locn, toks):
    self._funloc = locn

  #
  # Gets all the weaknesses
  #
  def get_all_weaknesses(self):
    return os.listdir (self.__testcase_dir__)   
