#!/bin/env python

################################################################################
#
# file : Exporter.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

#
#base class - Exporter
#
class Exporter:
  def __init__ (self, name):
    self.__name__ = name

  #
  # Name of the Exporter
  #
  def name (self):
    return self.__name__

  def __repr__(self):
    return self.__name__

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    pass

  #
  # Initialize the Exporter
  #
  def parse_args (self, args):
    self.__threads__ = args.threads
    if args.weaknesses:
      self.__weaknesses__ = args.weaknesses.split (',')
    else:
      self.__weaknesses__ = None

  #
  # Export the provided result set
  #
  def export (self, merged_rs, datapointset, filename):
    pass
