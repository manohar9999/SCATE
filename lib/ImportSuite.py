#!/bin/env python

################################################################################
#
# file : ImportSuite.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

#
#base class - ImportSuite
#
class ImportSuite:
  def __init__ (self, source):
    self.__weaknesses__ = None
    self.__source__ = source
    self.__basepath__ = '.'
    self.__threads__ = 1

  def getSource (self):
    return self.__source__

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    pass

  #
  # Initialize the ImportSuite
  #
  def parse_args (self, args):
    if (args.threads):
      self.__threads__ = args.threads

    if args.path:
      self.__basepath__ = args.path

    if args.weaknesses:
      self.__weaknesses__ = args.weaknesses.split (',')

  #
  # Type of Test Suite Parser
  #
  def import_testcases(Result_set, weakness_list):
    pass

  def getThreadCount (self):
    return self.__threads__

  #
  # Get the string representation of the import suite.
  #
  def __repr__ (self):
    return self.__source__