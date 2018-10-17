#!/bin/env python

################################################################################
#
# file : Command.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################

from ..Command import Command
from ..DataManagers.XMLManager import XMLManager
from .. import Utilities
from ..DataAbstractions import DataPointSet
import logging

#
# Factory Method for Command Build
#
def __create__ ():
  return ReportCommand ()

#
# Base class - Report
#
class ReportCommand (Command):
  def __init__ (self):
    super (ReportCommand, self).__init__ ('report', 'Generate a report from the result set')

  #
  # Initalize the parser
  #
  def init_parser (self, parser):
    report_parser = parser.add_parser ('report', help='Generate Reports')
    report_parser.add_argument ('--exportfile', type=str, required=True, help='Export file to use')
    report_parser.set_defaults (command=self)
    generator_parser = report_parser.add_subparsers (help='Generator specific commands')

    # Let the Tools modify the parser
    for generator in Utilities.get_reportgenerators ():
      logging.debug ('Expanding build command-line parsing using [%s]' % generator)
      generator.init_parser (generator_parser)


  #
  # Initialise DataManager based on arguments provided
  #
  def parse_args (self ,args):
    # Call the base class (Command) init
    super (ReportCommand, self).parse_args (args)
    self.__exportfile__ = args.exportfile
    self.__generator__ = args.generator ()
    self.__generator__.parse_args (args)

  #
  # Executes the command. This method is called after init
  #
  def execute (self):
    dpset = DataPointSet ()

    logging.info ('Loading export file [%s]' % self.__exportfile__)
    xmlm = XMLManager (self.__exportfile__)
    xmlm.read_datapointset (dpset)

    self.__generator__.generate (dpset)
