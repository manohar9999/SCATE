#!/usr/bin/env python3

###############################################################################
#
# file: SCAtool.py
#
# author:lveliche@iupui.edu
# reference: https://svn.cs.iupui.edu/repos/SEM/trunk/scripts/bczar/
#
###############################################################################

import sys
import os
import argparse
import logging

from lib.DynamicLoader import DynamicLoader

#
# Main entry point for the application.
#
def main ():
  logging.basicConfig(level=logging.INFO, format='[%(asctime)s] - %(message)s')

  # Build the command-line parser
  logging.debug ('Initializing command-line parser')
  parser = argparse.ArgumentParser ()

  # Initialize the argument parser with the generic options
  logging.debug ('Initializing argument parser with generic options')
  parser.add_argument ('--weaknesses', type=str, help='Comma-separated list of weaknesses to use')
  parser.add_argument ('--threads', type=int, default=1, help='Number of threads')
  parser.add_argument ('--debug', action='store_true', help='Enable debugging output')

  cmd_parser = parser.add_subparsers (help='Command-specific help')

  # Load all supported classes, and initialize the parser arguments
  # for each command.
  commandLoader = DynamicLoader (os.path.dirname (os.path.abspath(sys.argv[0])), 'lib/Commands')
  commandLoader.loadClasses ()

  for command in commandLoader.getClasses():
    command.init_parser (cmd_parser)

  # Parse the command-line arguments.
  args = parser.parse_args (sys.argv[1:])

  # Check for the debugging flag
  if args.debug:
    logging.root.setLevel (logging.DEBUG)

  command = args.command

  # Parse the command-line arguments for the command.
  logging.debug ('Initializing command [%s]' % command.name ())
  command.parse_args (args)

  # Now, execute the command.
  logging.info ('Executing command [%s]' % command.name ())
  command.execute ()

if __name__ == "__main__":
  main()
