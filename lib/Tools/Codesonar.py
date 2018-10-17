#!/bin/env python

################################################################################
#
# file : Codesonar.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################


from lib.Tool import Tool
from lib.DataAbstractions import File, Function, Line, Bug
from lib import Utilities

import logging
import urllib.request

import os
import csv


def __create__():
    return Codesonar()


#
# Worker function for multithreaded analysis
#
def run_worker(truth, tool, tool_name):
    return Codesonar().handle_weakness(truth, tool, tool_name)


#
# @class Codesonar
#
# Implementation for integrating Codesonar into the SCATE framework.
#
class Codesonar(Tool):
    #
    # Default constructor
    #
    def __init__(self):
        super(Codesonar, self).__init__(
            'codesonar',
            {
                'CWE14': ['Use of memset'],
                'CWE119': ['High Risk Loop', 'Negative Character Value'],
                'CWE120': ['Use of getopt', 'Use of getpass', 'Use of gets', 'Use of getwd', 'BSI OemToChar Rule Check',
                           'Use of realpath', 'Use of recvmsg', 'Use of strcat', 'Use of StrCatChainW', 'Use of strcmp',
                           'Use of strcpy', 'Use of strlen', 'Use of strtrns', 'Use of syslog', 'Buffer Overrun',
                           'Type Overrun'],
                'CWE124': ['Type Underrun'],
                'CWE126': ['Type Overrun'],
                'CWE127': ['Type Underrun'],
                'CWE134': ['Use of FormatMessage', 'Format String'],
                'CWE170': ['No Space For Null Terminator'],
                'CWE192': ['Cast Alters Value'],
                'CWE227': ['MAX_PATH Exceeded'],
                'CWE234': ['Dangerous Function Cast'],
                'CWE242': ['Use of AfxParseURL', 'Use of getopt', 'Use of getpass', 'Use of gets', 'Use of getwd',
                           'BSI OemToChar Rule Check', 'Use of realpath', 'Use of recvmsg', 'Use of strcat',
                           'Use of StrCatChainW', 'Use of strcmp', 'Use of strcpy', 'Use of strlen', 'Use of strtrns',
                           'Use of syslog', 'Use of catopen', 'Use of chroot', 'Use of CreateFile',
                           'Use of CreateProcess', 'Use of CreateThread', 'Use of FormatMessage', 'Use of setuid',
                           'Use of signal', 'Use of ttyname', 'Use of t_open', 'Use of vfork'],
                'CWE251': ['Use of strcat', 'Use of StrCatChainW', 'Use of strcmp', 'Use of strcpy', 'Use of strlen',
                           'Use of strtrns'],
                'CWE252': ['Ignored Return Value'],
                'CWE253': ['Ignored Return Value'],
                'CWE269': ['BSI AddAccess-ACE Rule Check'],
                'CWE284': ['Null Security Descriptor'],
                'CWE326': ['Use of crypt'],
                'CWE330': ['Use of crypt', 'Use of rand', 'Use of rand48 Function', 'Use of random'],
                'CWE366': ['Data Race'],
                'CWE367': ['File System Race Condition'],
                'CWE369': ['Division By Zero'],
                'CWE377': ['Use of GetTempFileName', 'Use of mktemp', 'Use of tmpfile', 'Use of tmpnam'],
                'CWE400': ['Potential Unbounded Loop'],
                'CWE401': ['Leak'],
                'CWE411': ['Double Lock', 'Double Unlock', 'Try-lock that will never succeed'],
                'CWE415': ['Double Free'],
                'CWE416': ['Use After Free'],
                'CWE426': ['Use of AfxLoadLibrary', 'Use of CoLoadLibrary', 'Use of execlp', 'Use of execvp',
                           'Use of LoadLibrary', 'Use of popen', 'Us', 'Use of ShellExecute', 'Use of system',
                           'Use of _exec', 'Use of _spawn'],
                'CWE452': ['Double Initialization'],
                'CWE457': ['Uninitialized Variable'],
                'CWE465': ['Return Pointer To Freed', 'High Risk Loop', 'Pointer Before Beginning of Object',
                           'Pointer Past End of Object'],
                'CWE476': ['Null Pointer Dereference', 'Unchecked Parameter Dereference'],
                'CWE477': ['Use of cuserid', 'Use of LoadModule', 'Use of MoveFile', 'Use of WinExec'],
                'CWE485': ['Scope Could Be File Static', 'Scope Could Be Local Static'],
                'CWE557': ['Deadlock', 'Blocking in Critical'],
                'CWE561': ['Unreachable Code'],
                'CWE562': ['Return Pointer To Local'],
                'CWE563': ['Unused Value'],
                'CWE570': ['Redundant Condition'],
                'CWE571': ['Redundant Condition'],
                'CWE590': ['Free Non-Heap Variable', 'Free Null Pointer'],
                'CWE592': ['Use of cuserid', 'Use of getlogin'],
                'CWE628': ['Dangerous Function Cast', 'Varargs Function Cast'],
                'CWE662': ['Blocking in Critical'],
                'CWE664': ['Misaligned Object'],
                'CWE666': ['Socket In Wrong State'],
                'CWE667': ['Nested Locks', 'Missing Lock Acquisition', 'Missing Lock Release', 'Conflicting Lock Order',
                           'Unknown Lock'],
                'CWE672': ['Double Close', 'Use After Close'],
                'CWE675': ['Double Initialization', 'Double Close'],
                'CWE680': ['Integer Overflow of Allocation Size'],
                'CWE686': ['Type Mismatch', 'Negative Character Value'],
                'CWE691': ['Use of longjmp', 'Use of setjmp'],
                'CWE696': ['Null Test After Dereference'],
                'CWE704': ['Dangerous Function Cast', 'Cast Alters Value', 'Varargs Function Cast'],
                'CWE710': ['Use of longjmp', 'Use of setjmp', 'Not All Warnings Are Enabled', 'Warnings',
                           'Lock/Unlock Mismatch', 'Negative File Descriptor', 'Not Enough Assertions', 'Recursion',
                           'Too Many Parameters', 'Function Too Long', 'Macro Uses Arrow Operator',
                           'Macro Uses [] Operator', 'Code Before #include', 'Conditional Compilation',
                           'Macro Defined in Function Body', 'Macro Does Not End With } or )', 'Macro Do',
                           'No Matching #endif', 'No Matching #if', 'Macro Uses ## Operator', 'Recursive Macro',
                           'Macro Uses Unary * Operator', 'Unbalanced Parenthesis', 'Use of #undef', 'Goto Statement',
                           'Multiple Declarations On Line', 'Multiple Statements On Line', 'Too Many Dereferences',
                           'Too Much Indirection in Declaration', 'Basic Numerical Type Used'],
                'CWE761': ['Misaligned Object'],
                'CWE762': ['Type Mismatch'],
                'CWE764': ['Double Lock', 'Locked Twice'],
                'CWE765': ['Double Unlock'],
                'CWE771': ['Leak'],
                'CWE773': ['Leak'],
                'CWE786': ['Buffer Underrun'],
                'CWE788': ['Buffer Overrun'],
                'CWE789': ['Unreasonable Size Argument']
            })

        # Map: CodeSonar project name ==> directory path on local filesystem
        self.projects = dict()

    #
    # Initialize the parser
    #
    def init_parser(self, parser):
        codesonar_parser = parser.add_parser('codesonar', help='use CodeSonar as the build tool')
        codesonar_parser.set_defaults(tool=self)
        codesonar_parser.add_argument('--server', type=str, required=True,
                                      help='location of CodeSonar server (server:port)')

    #
    # Parse the command-line arguments.
    #
    def parse_args(self, args):
        super(Codesonar, self).parse_args(args)

        self.__facts__ = []
        self.__server__ = args.server

    # {@ Build hooks

    #
    # Handle clean
    #
    def handle_clean(self, suite):
        logging.info('Cleaning suite [%s]' % suite.directory)
        suite_dir = os.path.abspath(os.path.join(self.__SCATE_root__, suite.directory))
        os.chdir(suite_dir)

        # Run 'make clean' in directories with a Makefile
        if suite.compiler == 'make':
            for root, subdirectories, files in os.walk(suite_dir):
                if "Makefile" in files:
                    os.chdir(root)
                    Utilities.run_cmd([suite.compiler, 'clean'])

        # Delete the analysis directory
        project_name = self.get_project_name(suite)
        analysis_dir = os.path.join(project_name, '.prj_files')
        if os.path.isdir(analysis_dir):
            import shutil
            logging.info('Deleting analysis directory [%s]', analysis_dir)
            shutil.rmtree(analysis_dir)

        os.chdir(self.__SCATE_root__)

    #
    # Compile the weakness using CodeSonar Tool
    #
    def handle_compile(self, suite):
        suite_dir = os.path.abspath(os.path.join(self.__SCATE_root__, suite.directory))

        logging.info('Compiling suite [%s] with tool [%s]' % (suite.directory, self.name()))

        self.run_build_in_tree(suite_dir, suite.compiler, suite.args)

        os.chdir(self.__SCATE_root__)

    def run_build_in_tree(self, directory_path, compiler, extra_args, recursive=True):
        """
        Walk the tree under 'directory', run 'build_command' where 'Makefile' exists.

        >>> import shutil
        >>> starting_directory = os.curdir
        >>> os.path.exists("/tmp/test_run_build_in_tree")
        False
        >>> os.makedirs('/tmp/test_run_build_in_tree/1/2/3/4/5/6/7/8/9/', exist_ok=True)
        >>> with open('/tmp/test_run_build_in_tree/1/2/3/4/5/6/7/8/Makefile', 'w+') as file:
        ...     file.write("TEST")
        4
        >>> with open('/tmp/test_run_build_in_tree/1/2/3/4/5/Makefile', 'w+') as file:
        ...     file.write("TEST")
        4
        >>> with open('/tmp/test_run_build_in_tree/1/2/3/Makefile', 'w+') as file:
        ...     file.write("TEST")
        4
        >>> tool = Codesonar()
        >>> build_command = ['echo', 'Running build command...']
        >>> tool.run_build_in_tree('/tmp/test_run_build_in_tree', build_command)
        3
        >>> True if os.curdir == starting_directory else False
        True
        >>> tool.run_build_in_tree('/tmp/test_run_build_in_tree/1/2/3', build_command, recursive=False)
        1
        >>> tool.run_build_in_tree('/tmp/test_run_build_in_tree/1/2/3/4/5', build_command)
        2
        >>> tool.run_build_in_tree('/tmp/test_run_build_in_tree/1/2/3/4/5/6/7/8', build_command)
        1
        >>> tool.run_build_in_tree('/tmp/test_run_build_in_tree/1/2/3/4/5/6/7/8/9', build_command)
        0
        >>> tool.run_build_in_tree('/tmp/test_run_build_in_tree/1/2/3/Makefile', build_command)
        Traceback (most recent call last):
        RuntimeError: /tmp/test_run_build_in_tree/1/2/3/Makefile is not a directory, cannot discover Makefile here
        >>> shutil.rmtree("/tmp/test_run_build_in_tree")

        :param directory_path: The tree to walk.
        :param compiler: The compiler to use (callable from shell)
        :param extra_args: Extra arguments to add to CodeSonar command.
        :param recursive: Run recursively in subdirectories found under `directory_path`
        """
        result = 0
        current_dir = os.curdir

        if os.path.isdir(directory_path):
            logging.debug("Discovered directory: %s" % directory_path)
        else:
            raise RuntimeError("%s is not a directory, cannot discover Makefile here" % directory_path)

        if recursive:
            # Find subdirectories under `directory_path`
            subdirs = filter(os.path.isdir,
                             [os.path.join(directory_path, file_obj) for file_obj in os.listdir(directory_path)]
                             )

            for subdir in subdirs:
                if 'prj_files' not in directory_path:
                    logging.debug("Discovered subdirectory '%s' in directory: %s" % (
                        subdir,
                        directory_path
                    ))

                    result += self.run_build_in_tree(os.path.join(directory_path, subdir),
                                                     compiler,
                                                     extra_args,
                                                     recursive)
                else:
                    logging.debug("Skipping CodeSonar build directory: %s " % directory_path)

        # TODO: Rework for for different compilers
        file_path = os.path.join(directory_path, 'Makefile')
        if os.path.exists(file_path):
            logging.debug("Found Makefile in directory: %s" % directory_path)

            logging.debug("Changing to directory: %s" % directory_path)
            os.chdir(directory_path)

            project_name = self.get_project_name(directory_path)
            logging.debug('Using project name [%s]' % project_name)
            self.projects[project_name] = directory_path
            build_command = ['codesonar', 'analyze', project_name, '-foreground', self.__server__, compiler, extra_args]

            # TODO: Rework for for different compilers
            if compiler == 'make' and self.__threads__ > 1:
                build_command.extend(['-j', '%s' % self.__threads__])

            logging.debug("Running %s in directory '%s'..." % (" ".join(build_command), os.curdir))
            Utilities.run_cmd(build_command)
            result += 1
        else:
            if not 'prj_files' in directory_path:
                file_count = len(
                    [name for name in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, name))])
                if file_count > 0:
                    logging.warning(
                        "NOTICE: Files in %s are not supported by CodeSonar (no Makefile found)" % directory_path)
            else:
                logging.debug("Skipping CodeSonar build directory: %s " % directory_path)

        if not current_dir == os.curdir:
            logging.debug("Changing directory back to %s..." % current_dir)
            os.chdir(current_dir)

        return result

    #
    # Get a unique project name for the provided suite
    #
    def get_project_name(self, directory):
        return directory.replace('/', '_').replace('\\', '_')

    #
    # Gather results from the server into the provided result set
    #
    def handle_docgen(self, suite):
        # Get build numbers and project name from the index
        logging.info('Generating build results for suite [%s]' % suite.directory)
        project_info = self.get_projects_from_server()

        for project_name in self.projects.keys():
            if not project_name in project_info.keys():
                logging.error('ERROR: Unable to find project %s on server' % project_name)
                return

            if project_info[project_name]['status'] != 'Finished':
                logging.error('ERROR: Analysis incomplete for project [%s], skipping' % project_name)
                return

            # Get the analysis results
            analysis = self.get_from_server('http://%s%s' % (self.__server__, project_info[project_name]['url']))
            reader = csv.reader(analysis[1:])

            for row in reader:
                # Example fields: ['score', 'id', 'class', 'rank', 'file', 'line number', 'procedure', 'priority', 'state', 'finding', 'owner', 'url']
                # Example values: ['70', '63.2844', 'Return Pointer to Local', 'Security', 'CWE562_Return_of_Stack_Variable_Address__return_buf_01.c', '17', 'helperBad', 'None', 'None', 'None', '', '/warninginstance/2844.txt?filter=3']

                prob_info = row[2]  # class of warning

                filename = os.path.join(self.projects[project_name], row[4])

                if not os.path.exists(filename):
                    logging.info("File %s not found, skipping row in CodeSonar project analysis results" % filename)
                    continue

                line = row[5]
                procedure = row[6]

                if '::' in procedure:
                    procedure = procedure.split('::')[-1]

                if filename not in suite.files:
                    suite[filename] = File(suite, filename)

                if procedure not in suite[filename].functions:
                    suite[filename][procedure] = Function(filename, procedure)

                if line not in suite[filename][procedure].lines:
                    suite[filename][procedure][line] = Line(procedure, line)

                suite[filename][procedure][line].add_Bug(Bug(prob_info, filename + ":" + line, prob_info))

        logging.info('Found [%s] bugs for suite [%s]' % (len(suite.get_Bugs()), suite.directory))

    #
    # Build a dict with project names and build numbers
    #
    def get_projects_from_server(self):
        # example: CWE843,Finished,Thu Mar 13 15:18:54 2014,24577,/analysis/436.csv?filter=2
        results = {}
        index = self.get_from_server('http://%s/index.csv' % self.__server__)
        reader = csv.reader(index)

        for row in reader:
            # Skip header
            if row[0] == 'name':
                continue

            project = row[0]
            status = row[1]
            # Drop query arguments from url
            url = row[4][:row[4].find('?')]

            results[project] = {'status': status, 'url': url}

        return results

    #
    # Get file from server
    #
    def get_from_server(self, url):
        # Requests return bytes instead of strings.  Splitting results in an extra
        # blank line at the end.
        logging.debug('Getting url from server: [%s]' % url)
        return urllib.request.urlopen(url).read().decode('utf-8').split('\n')[:-1]

    # @}

    #
    # Build reports using the appropriate
    # type of report generator
    #
    def report(self, type_, csv_input, ignore_error_flag):
        reportgenerators = Utilities.get_reportgenerators()
        if ignore_error_flag == False:
            print(
                "\nCurrently we have the functionality to capture and generate this inforamtion\nbut it needs to be integrated into our framework\nThanks for your patience")
        else:
            for generator in reportgenerators:
                if type_ == generator.name():
                    generator.parse_args(csv_input)
                    generator.generatereport()
