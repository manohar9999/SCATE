#!/bin/env python

################################################################################
#
# file : ImportCommands.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

from ..Command import Command
from ..DynamicLoader import DynamicLoader
from ..DataAbstractions import ResultSet, Weakness, Suite, Flaw
from ..DataManagers.XMLManager import XMLManager
from .. import Utilities

import logging
import os
import sys

#
# Factory Method for Command
#
def __create__ ():
  return ImportCommand ()

#
# Concrete class - ImportCommand derived from Command
#
class ImportCommand (Command):
  #
  # Default constructor
  #
  def __init__ (self):
    super (ImportCommand, self).__init__ ('import', 'Imports the flaws from given data source')

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    importParser = parser.add_parser ('import', help='import test suite into a knowledge-base')
    importParser.add_argument ('--outfile', type=str, required=True, help='target output file for generated knowledge base')
    importParser.add_argument ('--path', type=str, required=True,  help='root directory of test suite to be imported')
    importParser.add_argument ('--threads', type=int, help='number of threads to spawn for import')
    importParser.set_defaults (command=self)

    path = os.path.dirname (os.path.abspath(sys.argv[0]))
    importLoader = DynamicLoader (path, 'lib/testsuites')
    importLoader.loadClasses()

    # Let the testsuites modify the parser
    suiteParser = importParser.add_subparsers (help='Test Suites')

    for suite in importLoader.getClasses ():
      logging.debug ('Expanding import command-line parser using [%s]' % suite)
      suite.init_parser (suiteParser)

  #
  # Initializes the Import
  #
  def parse_args (self, args):
    super (ImportCommand, self).parse_args (args)

    self.__outfile__ = args.outfile
    self.__importsuite__ = args.suite
    self.__args__ = args

    # Pass the args to the importsuite
    self.__importsuite__.parse_args (args)

  #
  # Executes the command. This method is called after init
  #
  def execute (self):
    logging.info ('Importing ground truth using [%s]' % self.__importsuite__.getSource ())
    rs = ResultSet ('resultset', self.__importsuite__.getSource ())

    rs.args = Utilities.stringify_args (self.__args__)
    xmlm = XMLManager (self.__outfile__)

    # Append to an existing outfile if it exists
    if os.path.isfile (self.__outfile__):
      xmlm.add_results (rs, False)

    # Parse and write
    self.__importsuite__.import_testcases (rs)
    xmlm.write (rs)
