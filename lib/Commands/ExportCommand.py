#!/bin/env python

################################################################################
#
# file : ExportCommands.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

from ..DynamicLoader import DynamicLoader
from ..Command import Command
from ..DataAbstractions import *
from ..DataManagers.XMLManager import XMLManager

import logging
import os
import sys

#
# Factory Method for Command
#
def __create__ ():
  return ExportCommand ()

#
# Concrete class - ExportCommand derived from Command
#
class ExportCommand (Command):
  #
  # Default constructor
  #
  def __init__ (self):
    super (ExportCommand, self).__init__ ('export', 'Exports results for the provided import and build files')

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    subparser = parser.add_parser ('export', help='export result set for analysis')
    subparser.add_argument ('--importfiles', type=str, required=True, help='Comma-seperated list of import files')
    subparser.add_argument ('--buildfiles', type=str, required=True, help='Comma-seperated list of build file')
    subparser.add_argument ('--outfile', type=str, required=True, help='Output file')
    subparser.set_defaults (command=self)


    exportLoader = DynamicLoader (os.path.dirname (os.path.abspath(sys.argv[0])), 'lib/Exporters')
    exportLoader.loadClasses()

    exporterParser = subparser.add_subparsers (help='export formats')

    for exporter in exportLoader.getClasses ():
      logging.debug ('Expanding export command-line parser using [%s]' % exporter)
      exporter.init_parser (exporterParser)

  #
  # Initializes the Export
  #
  def parse_args (self, args):
    # Call the base class (Command) init
    super (ExportCommand, self).parse_args (args)
    self.__importfiles__ = args.importfiles
    self.__buildfiles__ = args.buildfiles
    self.__outfile__ = args.outfile
    self.__exporter__ = args.exporter
    self.__args__ = args

    # Pass the args to the importsuite
    self.__exporter__.parse_args (args)

  #
  # Executes the command. This method is called after init
  #
  def execute (self):
    dpset = DataPointSet ()
    rs = ResultSet ()

    for filename in self.__buildfiles__.split (','):
      # Read build file
      logging.info ('Loading build file [%s]' % filename)
      xmlm = XMLManager (filename)
      xmlm.add_results (rs, True)
      dpset.builds[rs.source] = rs.args

    for filename in self.__importfiles__.split (','):
      # Read import file
      logging.info ('Loading knowledge base [%s]' % filename)
      xmlm = XMLManager (filename)
      xmlm.add_results (rs, False)
      dpset.imports[rs.source] = rs.args

    # Let the exporter manage the process from here
    logging.info ('Exporting results using [%s]' % self.__exporter__.name ())
    self.__exporter__.export (rs, dpset, self.__outfile__)
