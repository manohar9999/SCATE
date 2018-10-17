import logging
import os

from pyparsing import *

from ..DataAbstractions import FlawType
from ..ImportSuite import ImportSuite


#
# @class Parser
#
# Base class for all importers of the Juliet C++ test cases.
#
class Parser:
    #
    # Initializing constructor
    #
    # @param[in]        id        Id associated with the parser
    #
    def __init__(self, source):
        self.__current_function__ = None
        self.__last_flaws__ = []
        self.__source__ = source

    def parse(self, file):
        #
        # Action for handling a C-style comment in the source file. This method
        # is attached to the C comment parser in pyparse via the setParseAction ().
        #
        def create_flaw_definition(flawString, flawLoc, flawResults):
            # noinspection PyUnusedLocal
            def set_flaw_severity(st, loc, result):
                result.severity = FlawType.Flaw

            # noinspection PyUnusedLocal,PyUnusedLocal
            def set_potential_flaw_severity(st, loc, result):
                result.severity = FlawType.Potential

            # noinspection PyUnusedLocal,PyUnusedLocal
            def set_incidental_flaw_severity(st, loc, result):
                result.severity = FlawType.Incidental

            # noinspection PyUnusedLocal,PyUnusedLocal
            def set_fix_severity_level(st, loc, result):
                result.severity = FlawType.Fix

            # noinspection PyUnusedLocal,PyUnusedLocal
            def create_flaw_from_string(st, loc, result):
                description = ' '.join(result[1])
                lineNumber = lineno(flawLoc, flawString)

                if not self.__current_function__:
                    self.__current_function__ = ''
                    logging.warning('Missing function for %s:%d' % (file.filename, lineNumber))

                function = file.get_function(self.__current_function__)
                line = function.get_line(lineNumber)
                flaw = line.add_flaw(result.severity, description, self.__source__)

                return flaw

            # Extract the text from the C-style comment.
            comment = flawResults[0][2:-2]

            # Define the different types of supported flaws. Currently, we support
            # the following types of flaws:
            #
            #  = FLAW
            #  = POTENTIAL FLAW
            #  = INCIDENTAL
            #  = FIX

            FLAW = Literal('FLAW').setParseAction(set_flaw_severity)
            INCIDENTAL = Literal('INCIDENTAL').setParseAction(set_incidental_flaw_severity)

            POTENTIAL_FLAW = Group(Literal('POTENTIAL') + Literal('FLAW'))
            POTENTIAL_FLAW.setParseAction(set_potential_flaw_severity)

            FIX = Literal('FIX').setParseAction(set_fix_severity_level)
            flawType = FLAW | POTENTIAL_FLAW | INCIDENTAL | FIX

            # Definition the flaw type, which is the flaw above and a colon.
            flawTypeDefinition = flawType + Optional(Literal(':').suppress())
            flawDescription = Group(OneOrMore(Word(printables)))
            flawDescription.setResultsName('description')

            # Define the flaw definition, which is the flaw definition and the
            # description of the flaw.
            flawDefinition = flawTypeDefinition + flawDescription
            flawDefinition.setParseAction(create_flaw_from_string)

            try:
                # Currently getting a list of flaw objects.  Since we don't get function and line with them
                # anymore, we need to refactor this
                flaws = flawDefinition.parseString(comment)
                self.__last_flaws__.extend(flaws)

                return flaws

            except ParseException:
                # Change the result to an empty string. Otherwise, the original
                # tokens will be added to the result set.
                return []

        #
        # The purpose of this function to check if the token is a function,
        # and cache it if it is a function.
        #
        def cache_token_if_function_name(st, loc, result):
            # If we have seen any flaws since the last token, we need to update
            # them with this line number. This is necessary because the flaw marker
            # is a comment. The real flaw therefore occurs on the line of the next
            # statement.
            if self.__last_flaws__:
                for flaw in self.__last_flaws__:
                    flaw.line.line = lineno(loc, st)

                self.__last_flaws__[:] = []

            # In some cases, the token may be a function without a space between the
            # the function name and the open parenthesis. We therefore need to check
            # if the token has an open parenthesis and remove it. We do not care about
            # what comes after the parenthesis.

            token = result[0]
            index = token.find('(')

            if index > -1:
                token = token[:index]

            # Now that we have a raw token with now extra information, let's check
            # if the token is a function of interest. We can cheat with the Juliet
            # test suite because the functions of interest have a well-defined format
            # that is consistent across all CWEs.
            if token.startswith('good') or token.startswith('bad') or token.startswith('CWE'):
                self.__current_function__ = token

        # Define the grammar/parser for a file that contains flaws.
        cStyleComment.setParseAction(create_flaw_definition)

        token = Word(printables)
        token.setParseAction(cache_token_if_function_name)
        fileDefinition = ZeroOrMore(token.suppress() ^ cStyleComment)

        # Parse the file. Print the number flaws, and information about each flaw.

        fullPath = file.computeFullPath()

        return fileDefinition.parseFile(fullPath)


#
# @class JulietCpp
#
# Base class for all Juliet C++ parsers.
#
class JulietCpp(ImportSuite):
    #
    # Initializing constructor.
    #
    def __init__(self, version):
        super(JulietCpp, self).__init__('JulietCpp-' + version)

        self.__current_suite__ = None
        self.__targets__ = []
        self.__juliet_version__ = version
        self.__testcase_dir__ = None

    #
    # Initialize the parser
    #
    def init_parser(self, parser):
        super(JulietCpp, self).init_parser(parser)

        julietParser = parser.add_parser(self.getSource(), help='use %s test suite' % self.getSource())
        julietParser.set_defaults(suite=self)

    #
    #
    # Parse the command-line arguments.
    #
    def parse_args(self, args):
        super(JulietCpp, self).parse_args(args)

        self.__testcase_dir__ = os.path.realpath(self.__basepath__)

        if self.__weaknesses__ is None:
            logging.info('No weaknesses provided, using all weaknesses in test suite')
            self.__weaknesses__ = self.get_all_weaknesses()

    #
    # Main entry point for import commands.  This should result in
    # populating the result set.
    #
    def import_testcases(self, kb):
        import threading
        from queue import Queue

        # The queue shared between the main thread, and the ParserThread
        # worker threads below.
        q = Queue()

        #
        # @class ParserThread
        #
        # Active object that parses files as they are added to a queue.
        #
        class ParserThread(threading.Thread):
            def __init__(self, name, source):
                super(ParserThread, self).__init__()

                self.__name__ = name
                self.__parser__ = Parser(source)
                self.__flaws__ = []

            #
            # Main entry point for the thread. This function blocks on getting
            # elements from the queue. When it gets an element from the queue,
            # it parses it and stores the flaws locally.
            #
            # noinspection PyUnusedLocal
            def run(self):
                logger = logging.getLogger(self.name())

                while True:
                    # Get the next item in the queue
                    file = q.get()

                    # noinspection PyBroadException
                    try:
                        # Parse the file, and extend our list with the flaws.
                        flaws = self.__parser__.parse(file)
                        logger.debug('Found %s flaw(s) in %s' % (len(flaws), file.filename))

                        self.__flaws__.append((file, flaws))

                    except Exception as e:
                        import traceback
                        traceback.print_exc()

                    finally:
                        # Notify the queue we are done with this task. This is so the client
                        # can return from its join.
                        q.task_done()

            def name(self):
                return self.__name__

            def flaws(self):
                return self.__flaws__

        # Create N parser threads. The threads will read <CWE,files> tuples
        # from the queue. It will the push <CWE, Flaw> only its local listing
        # After parsing each file, we will then combine each threads list to
        # create the final result set.
        logging.info('Processing data set with %d threads' % self.__threads__)
        threads = []

        for i in range(self.__threads__):
            thr = ParserThread('ParserThread-%d' % i, self.__source__)
            thr.daemon = True
            threads.append(thr)

            thr.start()

        # Iterate over each of the weaknesses we are to import. For each weakness,
        # locate all its files and add them to the queue. This will cause the threads
        # we created above to process each file and append it to its local result set.

        for weakness_name in self.__weaknesses__:

            # If the weakness is already in the result set, delete it
            if weakness_name in kb.weaknesses:
                logging.info('Found weakness [%s] in result set, deleting old results' % weakness_name)
                del kb.weaknesses[weakness_name]

            # Get the weakness from the suite.
            weakness = kb.get_weakness(weakness_name)

            # For this suite, the weakness name is the target subdirectory (i.e. NIST_Cpp/CWE121).
            directory = os.path.join(self.__testcase_dir__, weakness_name)
            if not os.path.isdir(directory):
                logging.warning('Weakness [%s] is not supported by this test suite', weakness_name)
                continue

            suite = weakness.get_suite(directory, 'make', 'all')

            for filename in self.get_files(directory):
                file = suite.get_file(filename)
                q.put(file)

        # We are going to wait until all items in the queue are processed.
        q.join()

        # Gather all the flaws into a single result set.
        total_flaws = 0
        for thr in threads:
            total_flaws += len(thr.flaws())

        logging.info("Imported total of %s flaws in path %s" % (
            total_flaws,
            self.__testcase_dir__
        ))

        return kb

    #
    # Default elements passed when ParseAction is called are st,locn,toks
    #
    # noinspection PyUnusedLocal,PyUnusedLocal
    def printloc(self, st, locn, toks):
        self._funloc = locn

    #
    # Gets all the weaknesses
    #
    def get_all_weaknesses(self):
        return os.listdir(self.__testcase_dir__)

    #
    # Get the files to parse in the provided directory
    #
    def get_files(self, directory):
        results = []

        # Get the files from the specified directories. We only care about
        # files that end with .c or .cpp, excluding main.

        for path in os.listdir(directory):
            if os.path.isdir(os.path.join(directory, path)):
                sub_results = self.get_files(os.path.join(directory, path))
                for sub_path in sub_results:
                    results.append(os.path.join(path, sub_path))

            if path.endswith(".c") or path.endswith(".cpp") and not path.startswith('main'):
                results.append(path)

        return results
