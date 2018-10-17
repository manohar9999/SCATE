#!/bin/env python

################################################################################
#
# file : ReportGenerator.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################

#
# Base class - ReportGenerator
#
class ReportGenerator:
  #
  # Initialize the parser
  #
  @staticmethod
  def init_parser (parser):
    pass

  #
  # Initialize the tool
  #
  def parse_args (self, args):
    self.__threads__ = args.threads
    if args.weaknesses:
      self.__weaknesses__ = args.weaknesses.split (',')
    else:
      self.__weaknesses__ = None

  # {@ Report Hooks

  #
  # Genearates Report of respective type
  #
  def generate (self, datapointset):
    pass

  # @}
