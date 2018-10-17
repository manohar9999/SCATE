#!/bin/env python

################################################################################
#
# file : Coverity.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################


from ..Tool import Tool
from ..DataAbstractions import ResultSet, Weakness, Suite, File, Function, Line, Flaw, Bug
from ..DataManagers.XMLManager import XMLManager
from ..DataManagers.CSVManager import CSVManager
from .. import Utilities

import logging
import os
import subprocess
import suds
from suds.client import Client
from suds.wsse import *
import docx

#
# Factory for Tools
# @returns Coverity object
#
def __create__ ():
  return Coverity ()

#
# @class Coverity
#
# Implementation of the Coverity tool for integration with SCATE.
#
class Coverity (Tool):
  #
  # Default constructor
  #
  def __init__ (self):
    super (Coverity, self).__init__ (
      'coverity',
      {
        'CWE20': ['TAINTED_SCALAR', 'TAINTED_STRING', 'USER_POINTER'],
        'CWE119': ['ARRAY_VS_SINGLETON', 'BAD_ALLOC_ARITHMETIC', 'COM.BSTR.CONV', 'INCOMPATIBLE_CAST', 'INTEGER_OVERFLOW', 'INVALIDATE_ITERATOR', 'MISMATCHED_ITERATOR', 'OVERRUN', 'OVERRUN_DYNAMIC', 'OVERRUN_STATIC', 'REVERSE_NEGATIVE'],
        'CWE120': ['BUFFER_SIZE', 'SIZECHECK', 'STRING_OVERFLOW', 'STRING_SIZE'],
        'CWE125': ['INTEGER_OVERFLOW', 'OVERRUN', 'OVERRUN_DYNAMIC', 'OVERRUN_STATIC'],
        'CWE129': ['NEGATIVE_RETURNS', 'REVERSE_NEGATIVE', 'TAINTED_SCALAR'],
        'CWE131': ['BAD_ALLOC_STRLEN', 'SIZECHECK'],
        'CWE134': ['PW.NON_CONST_PRINTF_FORMAT_STRING', 'TAINTED_STRING', 'TAINTED_STRING_WARNING'],
        'CWE170': ['BUFFER_SIZE', 'BUFFER_SIZE_WARNING', 'READLINK', 'SIZECHECK', 'STRING_NULL'],
        'CWE188': ['INCOMPATIBLE_CAST'],
        'CWE190': ['BAD_SHIFT', 'INTEGER_OVERFLOW', 'OVERFLOW_BEFORE_WIDEN', 'PW.INTEGER_OVERFLOW', 'PW.INTEGER_TOO_LARGE', 'PW.SHIFT_COUNT_TOO_LARGE'],
        'CWE194': ['SIGN_EXTENSION'],
        'CWE195': ['MISRA_CAST'],
        'CWE197': ['CHAR_IO', 'MISRA_CAST', 'NO_EFFECT'],
        'CWE243': ['CHROOT'],
        'CWE248': ['UNCAUGHT_EXCEPT'],
        'CWE252': ['CHECKED_RETURN'],
        'CWE253': ['BAD_COMPARE'],
        'CWE366': ['MISSING_LOCK'],
        'CWE367': ['TOCTOU'],
        'CWE369': ['DIVIDE_BY_ZERO', 'PW.DIVIDE_BY_ZERO'],
        'CWE377': ['SECURE_TEMP'],
        'CWE394': ['NEGATIVE_RETURNS', 'REVERSE_NEGATIVE'],
        'CWE398': ['COPY_PASTE_ERROR', 'ENUM_AS_BOOLEAN', 'MISMATCHED_ITERATOR', 'MIXED_ENUMS', 'NO_EFFECT', 'PASS_BY_VALUE', 'VIRTUAL_DTOR',], # 'PW.*'
        'CWE400': ['STACK_USE'],
        'CWE401': ['COM.BSTR.ALLOC.leak', 'CTOR_DTOR_LEAK', 'NO_EFFECT', 'SYMBIAN.CLEANUP_STACK.leak'],
        'CWE404': ['RESOURCE_LEAK'],
        'CWE415': ['SYMBIAN.CLEANUP_STACK.double_free', 'USE_AFTER_FREE'],
        'CWE416': ['COM.BAD_FREE', 'COM.BSTR.ALLOC.double_free', 'COM.BSTR.ALLOC.free_uninit', 'COM.BSTR.ALLOC.use_after_free', 'COM.BSTR.ALLOC.use_uninit', 'USE_AFTER_FREE', 'WRAPPER_ESCAPE'],
        'CWE456': ['NO_EFFECT'],
        'CWE457': ['PW.BRANCH_PAST_INITIALIZATION', 'UNINIT', 'UNINIT_CTOR'],
        'CWE459': ['DELETE_ARRAY', 'SYMBIAN.CLEANUP_STACK'],
        'CWE465': ['NO_EFFECT'],
        'CWE467': ['BAD_SIZEOF', 'SIZEOF_MISMATCH'],
        'CWE476': ['FORWARD_NULL', 'NULL_RETURNS', 'REVERSE_INULL'],
        'CWE480': ['CONSTANT_EXPRESSION_RESULT', 'NO_EFFECT'],
        'CWE481': ['PW.ASSIGN_WHERE_COMPARE_MEANT'],
        'CWE482': ['NO_EFFECT'],
        'CWE483': ['NESTING_INDENT_MISMATCH'],
        'CWE484': ['MISSING_BREAK'],
        'CWE561': ['DEADCODE', 'UNREACHABLE'],
        'CWE562': ['PW.RETURN_PTR_TO_LOCAL_TEMP', 'RETURN_LOCAL'],
        'CWE563': ['UNUSED_VALUE'],
        'CWE569': ['CONSTANT_EXPRESSION_RESULT', 'SIZEOF_MISMATCH'],
        'CWE570': ['NO_EFFECT', 'PW.UNSIGNED_COMPARE_WITH_NEGATIVE'],
        'CWE573': ['MISSING_RESTORE', 'OPEN_ARGS', 'VARARGS'],
        'CWE590': ['BAD_FREE'],
        'CWE597': ['BAD_COMPARE'],
        'CWE606': ['NEGATIVE_RETURNS', 'TAINTED_SCALAR'],
        'CWE617': ['LOCK'],
        'CWE628': ['BAD_COMPARE', 'PW.BAD_PRINTF_FORMAT_STRING'],
        'CWE633': ['COM.BSTR.ALLOC'],
        'CWE662': ['ATOMICITY'],
        'CWE665': ['NO_EFFECT'],
        'CWE667': ['LOCK', 'SLEEP'],
        'CWE670': ['STRAY_SEMICOLON'],
        'CWE672': ['USE_AFTER_FREE'],
        'CWE676': ['SECURE_CODING'],
        'CWE681': ['MISRA_CAST'],
        'CWE683': ['SWAPPED_ARGUMENTS'],
        'CWE685': ['PW.TOO_FEW_PRINTF_ARGS', 'PW.TOO_MANY_PRINTF_ARGS'],
        'CWE686': ['PW.PRINTF_ARG_MISMATCH'],
        'CWE687': ['NEGATIVE_RETURNS'],
        'CWE704': ['INCOMPATIBLE_CAST', 'PW.BAD_CAST', 'PW.CONVERSION_TO_POINTER_LOSES_BITS'],
        'CWE710': ['ASSIGN_NOT_RETURNING_STAR_THIS', 'BAD_OVERRIDE', 'COPY_WITHOUT_ASSIGN', 'HFA', 'MISSING_ASSIGN', 'MISSING_COPY', 'MISSING_RETURN', 'SELF_ASSIGN'],
        'CWE758': ['DELETE_VOID', 'EVALUATION_ORDER'],
        'CWE762': ['ALLOC_FREE_MISMATCH'],
        'CWE764': ['LOCK'],
        'CWE772': ['VIRTUAL_DTOR'],
        'CWE775': ['RESOURCE_LEAK'],
        'CWE783': ['CONSTANT_EXPRESSION_RESULT', 'SIZEOF_MISMATCH'],
        'CWE833': ['ORDER_REVERSAL'],
        'CWE835': ['INFINITE_LOOP']
      })

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    coverity_parser = parser.add_parser ('coverity', help='use Coverity as the build tool')
    coverity_parser.add_argument ('--server', type=str, required=True, help='location of Coverity server (server:port)')
    coverity_parser.add_argument ('--username', type=str, required=True, help='username to access the Coverity WebService')
    coverity_parser.add_argument ('--password', type=str, required=True, help='password to access the Coverity WebService')
    coverity_parser.set_defaults (tool=self)

  #
  # Parse the command-line arguments.
  #
  def parse_args (self, args):
    super (Coverity, self).parse_args (args)

    self.__username__ = args.username
    self.__password__ = args.password
    self.__server_port__ = args.server
    self.__server__ = args.server.split (':')[0]

    # Initalize the connection to the Coverity WebService
    security = suds.wsse.Security ()
    security.tokens.append (suds.wsse.UsernameToken (args.username, args.password))
    self.__config_svc__ = suds.client.Client ('http://%s/ws/v7/configurationservice?wsdl' % args.server)
    self.__defect_svc__ = suds.client.Client ('http://%s/ws/v7/defectservice?wsdl' % args.server)
    self.__config_svc__.set_options (wsse=security)
    self.__defect_svc__.set_options (wsse=security)


  # {@ Build hooks

  #
  # Handle clean
  #
  def handle_clean (self, suite):
    logging.info ('Cleaning suite [%s]' % suite.directory)
    suite_dir = os.path.abspath (os.path.join (self.__SCATE_root__, suite.directory))
    os.chdir (suite_dir)
    Utilities.run_cmd ([suite.compiler, 'clean'])

    # Delete the remote project
    project_name = self.get_project_name (suite)
    Utilities.run_cmd (['cov-manage-im', '--mode', 'projects', '--delete', '--name', project_name, '--host', self.__server__, '--user', self.__username__, '--password', self.__password__])
    Utilities.run_cmd (['cov-manage-im', '--mode', 'streams', '--delete', '--name', project_name, '--host', self.__server__, '--user', self.__username__, '--password', self.__password__])

    # Delete the analysis directory
    if (os.path.isdir ('emit')):
      import shutil
      logging.info ('Deleting analysis directory [%s]', os.path.join (suite.directory, 'emit'))
      shutil.rmtree ('emit')

    os.chdir (self.__SCATE_root__)

  #
  # Get a unique project name for the provided suite
  #
  def get_project_name (self, suite):
    # Just use the suite directory, since that is unique
    return suite.directory.replace ('/', '_').replace ('\\', '_')[1:]

  #
  # Compile the suite using Coverity
  #
  def handle_compile (self, suite):
    logging.info ('Compiling suite [%s] with tool [%s]' % (suite.directory, self.name ()))

    # Get into the correct directory
    suite_dir = os.path.abspath (os.path.join (self.__SCATE_root__, suite.directory))
    logging.debug ('Changing directory to [%s]' % suite_dir)
    os.chdir (suite_dir)

    project_name = self.get_project_name (suite)

    # Determine language and analyze command
    if suite.compiler == 'make':
      language = 'cpp'
      analyze = 'cov-analyze'
    else:
      language = 'java'
      analyze = 'cov-analyze-java'
      configure_cmd = ['cov-configure', '--compiler', '/usr/bin/java']
      Utilities.run_cmd (configure_cmd)

    # Create our project and stream
    stream_cmd = ['cov-manage-im', '--mode', 'streams', '--add', '--set', 'name:%s' % project_name,
                  '--set', 'language:%s' % language, '--host', self.__server__,
                  '--user', self.__username__, '--password', self.__password__]

    project_cmd = ['cov-manage-im', '--mode', 'projects', '--add', '--set',
                   'name:%s' % project_name, '--insert', 'stream:%s' % project_name,
                   '--host', self.__server__, '--user', self.__username__,
                   '--password', self.__password__]

    Utilities.run_cmd (stream_cmd)
    Utilities.run_cmd (project_cmd)

    # Build the code
    build_cmd = ['cov-build', '--dir', suite_dir , suite.compiler, suite.args]

    # @TODO: Stategize handling muple threads for various compilers
    if language == 'cpp' and self.__threads__ > 1:
      build_cmd.extend (['-j', '%s' % self.__threads__])

    Utilities.run_cmd (build_cmd)

    # Get the results
    results_cmd = [analyze, '--dir', suite_dir, '-all', '-j', str (self.__threads__)]
    Utilities.run_cmd (results_cmd)

    # Upload results to the server
    upload_cmd = ['cov-commit-defects', '--dir', suite_dir, '--host', self.__server__,
                  '--stream', project_name, '--user', self.__username__,
                  '--password', self.__password__]
    Utilities.run_cmd (upload_cmd)

    # Get back to SCATE root
    os.chdir (self.__SCATE_root__)

  #
  # Get the results from coverity server and writes
  # the results to an xml document
  #
  def handle_docgen (self, suite):
    logging.info ('Generating build results for suite [%s]' % suite.directory)

    defects = self.get_project_defects (suite)

    logging.info ('Found [%d] defects from Coverity' % len (defects))

    filter_spec = self.__defect_svc__.factory.create ('streamDefectFilterSpecDataObj')
    filter_spec.includeHistory = False
    filter_spec.includeDefectInstances = True

    stream_id_list = self.__defect_svc__.factory.create ('streamIdDataObj')
    stream_id_list.name = self.get_project_name (suite)
    filter_spec.streamIdList = [stream_id_list]

    for proj_defect in defects:
      checker = proj_defect.checkerName
      try:
        function = proj_defect.functionDisplayName
      except:
        function = ''

      stream_defects = self.__defect_svc__.service.getStreamDefects ([proj_defect.cid], [filter_spec])
      for stream_defect in stream_defects:
        for instance in stream_defect.defectInstances:
          for event in instance.events:
            filename = os.path.split (event.fileId.filePathname)[-1]
            line = event.lineNumber

            if not filename in suite.files:
              suite[filename] = File (filename)

            if not function in suite[filename].functions:
              suite[filename][function] = Function (function)

            if not line in suite[filename][function].lines:
              suite[filename][function][line] = Line (line)

            suite[filename][function][line].add_Bug (Bug (checker))

    logging.info ('Found [%s] bugs for suite [%s]' % (len (suite.get_Bugs ()), suite.directory))

  #
  # Get project results from Coverity
  # 
  def get_project_defects (self, suite):
    results = []
    project_name = self.get_project_name (suite)

    # Get all the defects in a project
    project_id = self.__defect_svc__.factory.create ('projectIdDataObj')
    project_id.name = project_name

    page_spec = self.__defect_svc__.factory.create ('pageSpecDataObj')
    page_spec.startIndex = 0
    page_spec.pageSize = 1 # Maximum elements per page

    defects = self.__defect_svc__.service.getMergedDefectsForProject (project_id, None ,page_spec)

    while (len (results) != defects.totalNumberOfRecords):
      defects = self.__defect_svc__.service.getMergedDefectsForProject (project_id, None ,page_spec)
      results.extend (defects.mergedDefects)
      page_spec.startIndex += len (defects.mergedDefects)

    return results

  # @}
