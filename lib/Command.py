#!/bin/env python

################################################################################
#
# file : Command.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################


#
# Base class - Command
#
class Command:
  #
  # Initializing constructor
  #
  # @param[in]        name            Name of the command
  # @param[in]        description     Description of the command
  #
  def __init__ (self, name, description = None):
    self.__name__ = name
    self.__description__ = description

  #
  # Get the name of Command
  #
  def name (self):
    return self.__name__

  #
  # Get the description of the command
  #
  def description (self):
    return self.__description__

  #
  # Initalize the parser
  #
  def init_parser (self, parser):
    pass

  #
  # Initialize the command based on arguments provided
  #
  def parse_args (self, args):
    self.__threads__ = args.threads
    if args.weaknesses:
      self.__weaknesses__ = args.weaknesses.split (',')
    else:
      self.__weaknesses__ = None

  #
  # Executes the command. This method is called after init
  #
  def execute (self):
    pass

  #
  # Get the string representation of the object.
  def __repr__ (self):
    return self.__name__
