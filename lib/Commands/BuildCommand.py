    #!/bin/env python

################################################################################
#
# file : BuildCommand.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

from ..Command import Command
from ..DynamicLoader import DynamicLoader
from ..DataManagers.XMLManager import XMLManager
from ..DataAbstractions import ResultSet, Weakness, Suite
from .. import Utilities

import logging
import os.path
import sys


#
# Factory Method for Command Build
#
def __create__():
    return BuildCommand()


#
# Concrete class - Build derived from Command
#
class BuildCommand(Command):
    def __init__(self):
        super(BuildCommand, self).__init__('build', 'Builds the projects specified')

    #
    # Initialize the parser
    #
    def init_parser(self, parser):
        buildParser = parser.add_parser('build', help='build test suite against static code analysis tool')
        buildParser.add_argument('--importfile', type=str, required=True, help='Import result file to use')
        buildParser.add_argument('--outfile', type=str, required=True, help='Output file')
        buildParser.add_argument('--ignore-compile', action='store_true', help='Skip compilation')
        buildParser.add_argument('--ignore-docgen', action='store_true', help='Skip generation of the result file')
        buildParser.add_argument('--clean', action='store_true', help='Clean the directory prior to building')
        buildParser.set_defaults(command=self)

        toolParser = buildParser.add_subparsers(help='tool specific commands')

        toolLoader = DynamicLoader(os.path.dirname(os.path.abspath(sys.argv[0])), 'lib/Tools')
        toolLoader.loadClasses()

        # Let the Tools modify the parser
        for tool in toolLoader.getClasses():
            logging.debug('Expanding build command-line parsing using [%s]' % tool.name())
            tool.init_parser(toolParser)

    #
    # Initialises  based on arguments provided
    #
    def parse_args(self, args):
        # Call the base class (Command) init
        super(BuildCommand, self).parse_args(args)

        self.__importfile__ = args.importfile
        self.__outfile__ = os.path.abspath(args.outfile)
        self.__ignore_compile__ = args.ignore_compile
        self.__ignore_docgen__ = args.ignore_docgen
        self.__clean__ = args.clean
        self.__tool__ = args.tool
        self.__args__ = args

        # Pass the args to the importsuite
        self.__tool__.parse_args(args)

    #
    # Executes the command. This method is called after init
    #
    def execute(self):
        logging.debug('Importing ground truth from [%s]' % self.__importfile__)

        if not os.path.isfile(self.__importfile__):
            logging.error('ERROR: Build command called with invalid source file [%s]' % self.__importfile__)

        # The ground truth result set contains the suites which defines how and where to compile
        # the test implementations
        truth = ResultSet('resultset', 'ground_truth')
        xmlm = XMLManager(self.__importfile__)
        xmlm.add_results(truth, True)

        results = self.__tool__.build_result_set()
        print(self.__args__)

        results.args = Utilities.stringify_args(self.__args__)

        for weakness in self.get_weaknesses(truth):
            if not self.__tool__.supports_weakness(weakness):
                logging.warning('[%s] is not supported by tool [%s]' % (weakness.name, self.__tool__.name()))
                continue

            results[weakness.name] = Weakness(results, weakness.name)

            for suite in weakness.iterate_Suites():
                res_suite = Suite(results[weakness.name], suite.directory, suite.compiler, suite.args)
                results[weakness.name][suite.directory] = res_suite

                if self.__clean__:
                    self.__tool__.handle_clean(res_suite)

                if not self.__ignore_compile__:
                    self.__tool__.handle_compile(res_suite)

                if not self.__ignore_docgen__:
                    self.__tool__.handle_docgen(res_suite)

        if not self.__ignore_docgen__:
            # Handle writing the results
            xmlm = XMLManager(self.__outfile__)
            xmlm.write(results)

    #
    # Return the weaknesses to use within the provided result set
    #
    def get_weaknesses(self, result_set):
        for weakness in result_set.iterate_Weaknesses():
            if (not self.__weaknesses__) or (weakness.name in self.__weaknesses__):
                yield weakness
