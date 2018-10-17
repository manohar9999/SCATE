#!/bin/env python

################################################################################
#
# file : Klocwork.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################


from ..Tool import Tool
from ..DataAbstractions import ResultSet, Weakness, Suite, File, Function, Line, Flaw, FlawType, Bug, Granularity
from ..DataManagers.XMLManager import XMLManager
from ..DataManagers.CSVManager import CSVManager
from .. import Utilities
from lxml import objectify
import os
import subprocess
import urllib.request, urllib.parse, urllib.error, urllib.request, urllib.error, urllib.parse, json, sys, getpass

import logging
import sys

#
# Factory for Klocwork Tools
# @returns Klocwork object
#
def __create__ ():
  return Klocwork ()

#
# @param in:host:hostid,port:portnumber,user:user
# @returns token for the user to Login
#
def getToken (host, port, user) :
  ltoken = os.path.normpath(os.path.expanduser("~/.klocwork/ltoken"))
  ltokenFile = open (ltoken, 'r')
  for r in ltokenFile :
    rd = r.strip ().split (';')
    if rd[0] == host and rd[1] == str (port) and rd[2] == user :
      ltokenFile.close ()
      return rd[3]
  ltokenFile.close ()

#
# @paramin:jsonobject
# @returns: returns object of type issue
# which has all information about flaw
#
def from_json (json_object) :
  if 'id' in json_object:
    return Issue (json_object)
  return json_object

#
# Issue Class: contain all the attribs returned by
# Klocwork server
#
class Issue (object) :
  #
  # Intialises member variables with of class
  # with attributess returned by the server
  #
  def __init__ (self, attrs) :
    self.id = attrs["id"]
    self.message = attrs["message"]
    self.file = attrs["file"]
    self.method = attrs["method"]
    self.code = attrs["code"]
    self.severity = attrs["severity"]
    self.severityCode = attrs["severityCode"]
    self.state = attrs["state"]
    self.status = attrs["status"]
    self.taxonomyName = attrs["taxonomyName"]
    self.url = attrs["url"]

  #
  # Cutomised print method for Issue class
  # whenever print () is called on this class object
  # this is returned
  #
  def __str__ (self) :
    return "[%d] %s\n\t%s | %s\n\tChecker Code: %s | Severity: %s(%d) | State: %s | Status: %s | Taxonomy: %s\n\t%s" % (
    self.id, self.message, self.file, self.method, self.code, self.severity, self.severityCode, self.state,
    self.status, self.taxonomyName, self.url)

#
# @class Klocwork
#
# Concrete class for Tools -Klocwork- To build and analyse
#
class Klocwork (Tool):
  #
  # Default constructor.
  #
  def __init__ (self):
    super (Klocwork, self).__init__ (
      'klocwork',
      {
        'CWE20':['SV.BANNED.RECOMMENDED.SCANF', 'MISRA.STDLIB.ATOI'],
        'CWE22':['SV.DLLPRELOAD.NONABSOLUTE.DLL', 'SV.DLLPRELOAD.NONABSOLUTE.EXE', 'SV.DLLPRELOAD.SEARCHPATH'],
        'CWE23':['SV.DLLPRELOAD.NONABSOLUTE.DLL', 'SV.DLLPRELOAD.NONABSOLUTE.EXE', 'SV.DLLPRELOAD.SEARCHPATH'],
        'CWE73':['SV.DLLPRELOAD.NONABSOLUTE.DLL', 'SV.DLLPRELOAD.NONABSOLUTE.EXE', 'SV.DLLPRELOAD.SEARCHPATH', 'SV.TOCTOU.FILE_ACCESS'],
        'CWE77':['SV.CODE_INJECTION.SHELL_EXEC', 'SV.TAINTED.INJECTION'],
        'CWE78':['NNTS.TAINTED', 'SV.CODE_INJECTION.SHELL_EXEC', 'SV.TAINTED.INJECTION'],
        'CWE88':['NNTS.TAINTED', 'SV.CODE_INJECTION.SHELL_EXEC', 'SV.TAINTED.INJECTION'],
        'CWE114':['SV.DLLPRELOAD.NONABSOLUTE.DLL', 'SV.DLLPRELOAD.NONABSOLUTE.EXE', 'SV.DLLPRELOAD.SEARCHPATH'],
        'CWE119':['ABV.ANY_SIZE_ARRAY', 'ABV.STACK', 'ABV.GENERAL', 'ABV.TAINTED', 'ABV.ITERATOR', 'SV.TAINTED.LOOP_BOUND', 'SV.STRBO.BOUND_SPRINTF', 'SV.STRBO.UNBOUND_COPY', 'SV.STRBO.UNBOUND_SPRINTF', 'NNTS.MIGHT', 'NNTS.MUST'],
        'CWE120':['ABV.GENERAL', 'ABV.MEMBER', 'NNTS.TAINTED', 'NNTS.MIGHT', 'SV.STRBO.BOUND_COPY.OVERFLOW', 'SV.STRBO.UNBOUND_COPY', 'SV.STRBO.UNBOUND_SPRINTF', 'SV.UNBOUND_STRING_INPUT.CIN', 'SV.UNBOUND_STRING_INPUT.FUNC'],
        'CWE121':['ABV.STACK'],
        'CWE122':['ABV.GENERAL', 'ABV.STACK'],
        'CWE129':['SV.TAINTED.ALLOC_SIZE', 'ABV.TAINTED', 'SV.TAINTED.CALL.INDEX_ACCESS', 'SV.TAINTED.INDEX_ACCESS'],
        'CWE131':['INCORRECT.ALLOC_SIZE'],
        'CWE134':['SV.TAINTED.FMTSTR', 'SV.FMTSTR.GENERIC'],
        'CWE135':['SV.FMT_STR.BAD_SCAN_FORMAT'],
        'CWE170':['NNTS.TAINTED', 'NNTS.MIGHT', 'NNTS.MUST', 'SV.STRBO.BOUND_COPY.UNTERM', 'SV.STRBO.BOUND_SPRINTF', 'SV.STRBO.UNBOUND_SPRINTF'],
        'CWE176':['ABV.UNICODE.BOUND_MAP', 'ABV.UNICODE.FAILED_MAP', 'ABV.UNICODE.NNTS_MAP', 'ABV.UNICODE.SELF_MAP'],
        'CWE190':['INCORRECT.ALLOC_SIZE', 'SV.TAINTED.ALLOC_SIZE', 'ABV.TAINTED', 'SV.TAINTED.CALL.INDEX_ACCESS', 'SV.TAINTED.INDEX_ACCESS'],
        'CWE192':['SV.BANNED.RECOMMENDED.SCANF', 'PRECISION.LOSS', 'PRECISION.LOSS.CALL', 'MISRA.CVALUE.IMPL.CAST', 'MISRA.CAST.INT', 'MISRA.CAST.UNSIGNED_BITS', 'MISRA.UMINUS.UNSIGNED'],
        'CWE193':['NNTS.MIGHT', 'NNTS.MUST', 'SV.STRBO.BOUND_SPRINTF', 'SV.STRBO.UNBOUND_SPRINTF', 'SV.STRBO.UNBOUND_COPY'],
        'CWE195':['ABV.GENERAL'],
        'CWE197':['PRECISION.LOSS', 'PRECISION.LOSS.CALL', 'MISRA.CVALUE.IMPL.CAST', 'MISRA.CAST.INT', 'MISRA.CAST.UNSIGNED_BITS', 'MISRA.UMINUS.UNSIGNED'],
        'CWE242':['SV.PIPE.VAR', 'SV.FIU.PROCESS_VARIANTS', 'SV.STRBO.UNBOUND_COPY', 'SV.UNBOUND_STRING_INPUT.CIN', 'SV.UNBOUND_STRING_INPUT.FUNC', 'SV.USAGERULES.PROCESS_VARIANTS', 'SV.STRBO.UNBOUND_SPRINTF'],
        'CWE247':['SV.USAGERULES.SPOOFING'],
        'CWE250':['SV.USAGERULES.PERMISSIONS', 'SV.USAGERULES.PROCESS_VARIANTS', 'SV.FIU.PROCESS_VARIANTS'],
        'CWE251':['ABV.GENERAL'],
        'CWE252':['SV.RVT.RETVAL_NOTTESTED'],
        'CWE253':['SV.RVT.RETVAL_NOTTESTED'],
        'CWE272':['SV.BRM.HKEY_LOCAL_MACHINE'],
        'CWE273':['SV.FIU.PROCESS_VARIANTS', 'SV.USAGERULES.PERMISSIONS'],
        'CWE290':['SV.WEAK_CRYPTO.WEAK_HASH'],
        'CWE326':['SV.USAGERULES.SPOOFING'],
        'CWE362':['CONC.DL'],
        'CWE366':['CONC.DL'],
        'CWE367':['SV.TOCTOU.FILE_ACCESS'],
        'CWE377':['SV.PCC.CONST', 'SV.PCC.INVALID_TEMP_PATH', 'SV.PCC.MISSING_TEMP_CALLS.MUST', 'SV.PCC.MISSING_TEMP_FILENAME', 'SV.PCC.MODIFIED_BEFORE_CREATE'],
        'CWE390':['SV.RVT.RETVAL_NOTTESTED'],
        'CWE391':['SV.RVT.RETVAL_NOTTESTED'],
        'CWE401':['FREE.INCONSISTENT', 'MLK.MIGHT', 'MLK.MUST'],
        'CWE403':['RH.LEAK'],
        'CWE404':['FMM.MIGHT', 'FMM.MUST', 'RH.LEAK', 'SV.INCORRECT_RESOURCE_HANDLING.URH', 'SV.INCORRECT_RESOURCE_HANDLING.WRONG_STATUS', 'CONC.DL'],
        'CWE415':['UFM.DEREF.MIGHT', 'UFM.DEREF.MUST', 'UFM.FFM.MIGHT', 'UFM.FFM.MUST', 'UFM.RETURN.MIGHT', 'UFM.RETURN.MUST', 'UFM.USE.MIGHT', 'UFM.USE.MUST', 'MLK.MIGHT', 'MLK.MUST'],
        'CWE416':['UFM.DEREF.MIGHT', 'UFM.DEREF.MUST', 'UFM.FFM.MIGHT', 'UFM.FFM.MUST', 'UFM.RETURN.MIGHT', 'UFM.RETURN.MUST', 'UFM.USE.MIGHT', 'UFM.USE.MUST'],
        'CWE421':['SV.PIPE.VAR', 'SV.PIPE.CONST'],
        'CWE457':['UNINIT.CTOR.MIGHT', 'UNINIT.CTOR.MUST', 'UNINIT.HEAP.MIGHT', 'UNINIT.HEAP.MUST', 'UNINIT.STACK.MIGHT', 'UNINIT.STACK.MUST'],
        'CWE464':['SV.BANNED.RECOMMENDED.TOKEN', 'NNTS.MIGHT', 'NNTS.MUST'],
        'CWE466':['PORTING.CAST.PTR'],
        'CWE467':['INCORRECT.ALLOC_SIZE'],
        'CWE468':['CWARN.ALIGNMENT', 'MISRA.PTR.ARITH'],
        'CWE476':['NPD.CHECK.CALL.MIGHT', 'NPD.CHECK.CALL.MUST', 'NPD.CHECK.MIGHT', 'NPD.CHECK.MUST', 'NPD.CONST.CALL', 'NPD.CONST.DEREF', 'NPD.FUNC.CALL.MIGHT', 'NPD.FUNC.CALL.MUST', 'NPD.FUNC.MIGHT', 'NPD.FUNC.MUST', 'NPD.GEN.CALL.MIGHT', 'NPD.GEN.CALL.MUST', 'NPD.GEN.MIGHT', 'NPD.GEN.MUST', 'RN.INDEX', 'RNPD.CALL', 'RNPD.DEREF'],
        'CWE478':['LA_UNUSED'],
        'CWE479':['MISRA.EXPANSION.UNSAFE', 'MISRA.STDLIB.LONGJMP'],
        'CWE480':['ASSIGCOND.CALL', 'ASSIGCOND.GEN', 'EFFECT', 'SEMICOL', 'CWARN.NULLCHECK.FUNCNAME'],
        'CWE482':['ASSIGCOND.CALL', 'ASSIGCOND.GEN', 'EFFECT'],
        'CWE488':['CONC.DL'],
        'CWE497':['SV.STR_PAR.UNDESIRED_STRING_PARAMETER'],
        'CWE561':['UNREACH.GEN', 'UNREACH.RETURN', 'VA_UNUSED.GEN', 'VA_UNUSED.INIT', 'LA_UNUSED'],
        'CWE562':['LOCRET.ARG', 'LOCRET.GLOB', 'LOCRET.RET'],
        'CWE563':['LV_UNUSED.GEN'],
        'CWE587':['PORTING.CAST.PTR'],
        'CWE590':['FNH.MIGHT', 'FNH.MUST', 'FUM.GEN.MIGHT', 'FUM.GEN.MUST'],
        'CWE606':['SV.TAINTED.CALL.LOOP_BOUND', 'SV.TAINTED.LOOP_BOUND'],
        'CWE628':['MISRA.FUNC.UNMATCHED.PARAMS'],
        'CWE665':['UNINIT.STACK.ARRAY.MIGHT', 'UNINIT.STACK.ARRAY.MUST', 'UNINIT.STACK.ARRAY.PARTIAL.MUST', 'UNINIT.HEAP.MIGHT', 'UNINIT.HEAP.MUST', 'ABV.GENERAL'],
        'CWE676':['SV.BANNED.RECOMMENDED.SCANF', 'MISRA.STDLIB.ATOI'],
        'CWE681':['PRECISION.LOSS', 'PRECISION.LOSS.CALL'],
        'CWE682':['PORTING.UNSIGNEDCHAR.OVERFLOW.FALSE', 'MISRA.FUNC.VARARG', 'MISRA.SIGNED_CHAR.NOT_NUMERIC'],
        'CWE684':['SV.BANNED.RECOMMENDED.ALLOCA', 'SV.BANNED.REQUIRED.CONCAT', 'SV.BANNED.REQUIRED.COPY', 'SV.BANNED.REQUIRED.ISBAD', 'SV.BANNED.RECOMMENDED.NUMERIC', 'SV.BANNED.RECOMMENDED.OEM', 'SV.BANNED.RECOMMENDED.PATH', 'SV.BANNED.RECOMMENDED.SCANF', 'SV.BANNED.RECOMMENDED.SPRINTF', 'SV.BANNED.RECOMMENDED.TOKEN'],
        'CWE686':['SV.FMT_STR.BAD_SCAN_FORMAT', 'SV.FMT_STR.SCAN_FORMAT_MISMATCH.BAD', 'SV.FMT_STR.SCAN_FORMAT_MISMATCH.UNDESIRED', 'SV.FMT_STR.SCAN_IMPROP_LENGTH', 'SV.FMT_STR.SCAN_PARAMS_WRONGNUM.FEW', 'SV.FMT_STR.SCAN_PARAMS_WRONGNUM.MANY', 'SV.FMT_STR.PRINT_FORMAT_MISMATCH.BAD', 'SV.FMT_STR.PRINT_FORMAT_MISMATCH.UNDESIRED', 'SV.FMT_STR.UNKWN_FORMAT', 'SV.FMT_STR.UNKWN_FORMAT.SCAN'],
        'CWE704':['MISRA.CAST.CONST'],
        'CWE732':['SV.USAGERULES.PERMISSIONS'],
        'CWE754':['SV.RVT.RETVAL_NOTTESTED'],
        'CWE762':['FMM.MIGHT', 'FMM.MUST'],
        'CWE764':['CONC.DL'],
        'CWE768':['MISRA.LOGIC.SIDEEFF'],
        'CWE770':['RH.LEAK'],
        'CWE772':['CONC.DL'],
        'CWE787':['ABV.GENERAL'],
        'CWE788':['ABV.GENERAL', 'ABV.ANY_SIZE_ARRAY', 'ABV.STACK', 'ABV.TAINTED', 'SV.TAINTED.ALLOC_SIZE', 'SV.TAINTED.CALL.INDEX_ACCESS', 'SV.TAINTED.CALL.LOOP_BOUND', 'SV.TAINTED.INDEX_ACCESS'],
        'CWE805':['ABV.GENERAL', 'ABV.ANY_SIZE_ARRAY', 'ABV.STACK', 'ABV.TAINTED', 'SV.TAINTED.ALLOC_SIZE', 'SV.TAINTED.CALL.INDEX_ACCESS', 'SV.TAINTED.CALL.LOOP_BOUND', 'SV.TAINTED.INDEX_ACCESS', 'ABV.ITERATOR', 'INCORRECT.ALLOC_SIZE'],
        'CWE835':['INFINITE_LOOP.GLOBAL', 'INFINITE_LOOP.LOCAL', 'INFINITE_LOOP.MACRO']
      })

  #
  # Parse the command-line arguments.
  #
  def parse_args (self, args):
    super (Klocwork, self).parse_args (args)

    self.__server__ = args.server
    self.__server_url__ = 'http://%s' % self.__server__

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    klocwork_parser = parser.add_parser ('klocwork', help='use Klocwork as the build tool')
    klocwork_parser.add_argument ('--server', type=str, required=True, help='Klocwork server address and port [server:port]')
    klocwork_parser.set_defaults (tool=self)

  #
  # Clean the provided suite.  For Klocwork, that includes deleting
  # the project from the server 
  #
  def handle_clean (self, suite):
    logging.info ('Cleaning suite [%s]' % suite.directory)

    # Clean the compiled code
    suite_dir = os.path.abspath (os.path.join (self.__SCATE_root__, suite.directory ))
    os.chdir (suite_dir)
    Utilities.run_cmd ([suite.compiler, 'clean'])
   
    # Delete the remote project
    project_name = self.get_project_name (suite)
    del_cmd = ['kwadmin', '--url', self.__server_url__, 'delete-project', project_name]
    Utilities.run_cmd (del_cmd)

    # Delete the analysis directory
    if (os.path.isdir ('my_tables')):
      import shutil
      logging.info ('Deleting analysis directory [%s]', os.path.join (suite.directory, 'my_tables'))
      shutil.rmtree ('my_tables')

    os.chdir (self.__SCATE_root__)

  #
  # Compile the suite using Klocwork
  #
  def handle_compile (self, suite):
    logging.info ('Compiling suite [%s] with tool [%s]' % (suite.directory, self.name ()))

    # Get into the correct directory
    suite_dir = os.path.abspath (os.path.join (self.__SCATE_root__, suite.directory))
    logging.debug ('Changing directory to [%s]' % suite_dir)
    os.chdir (suite_dir)

    project_name = self.get_project_name (suite)

    # Create our project
    create_cmd = ['kwadmin', '--url', self.__server_url__, 'create-project', project_name]
    Utilities.run_cmd (create_cmd)

    # Identify the correct wrapper and build
    if suite.compiler == 'ant':
      wrapper = 'kwant'
    else:
      wrapper = 'kwinject'
    build_cmd = [wrapper, suite.compiler, suite.args]

    # @TODO: Stategize handling muple threads for various compilers
    if wrapper == 'kwinject' and self.__threads__ > 1:
      build_cmd.extend (['-j', '%s' % self.__threads__])

    Utilities.run_cmd (build_cmd) 

    # Get the results
    results_cmd = ['kwbuildproject', '--url', '%s/%s' % (self.__server_url__, project_name), '-o', 'my_tables', '%s.out' % wrapper]
    Utilities.run_cmd (results_cmd)

    # Upload results to the server
    upload_cmd = ['kwadmin', '--url', self.__server_url__, 'load', project_name, 'my_tables']
    Utilities.run_cmd (upload_cmd)

    # Get back to SCATE root
    os.chdir (self.__SCATE_root__)

  #
  # Get a unique project name for the provided suite
  #
  def get_project_name (self, suite):
    # Project names cannot exceed 64 characters
    # This becomes a problem with some NIST directory names, as some of them
    # are really long (i.e. 69 characters).

    # Get a relative path from SCATE_root
    suite_dir = os.path.normpath (suite.directory)
    source = suite_dir.replace (self.__SCATE_root__, '')

    # NIST implementation directories are CWE[#]_[desc_with_underscores]
    # Remove anything after the first '_' to shorten the name
    result = []
    for directory in source.split (os.sep):
      if 'CWE' in directory and '_' in directory:
        result.append (directory.split ('_')[0])
      else:
        result.append (directory)

    # * is splat operator, used to work around join taking comma-seperated strings
    # instead of a list
    source = os.path.join (*result)

    # / and \ are not allowed in project names, convert them to '_'
    return source.replace ('/', '_').replace ('\\', '_')

  #
  # Gets the results from klocwork Server and writes
  # the results to xml document
  #
  def handle_docgen (self, suite):
    logging.info ('Generating build results for suite [%s]' % suite.directory)

    url = '%s/review/api' % self.__server_url__
    host, port = self.__server__.split (':')
    loginToken = getToken (host, port, getpass.getuser ())
    query = {'user': getpass.getuser (), 'action': 'search', 'ltoken': loginToken}

    # Build the query
    project_name = self.get_project_name (suite)
    query['project'] = project_name
    query['query'] = 'severity:1-3'
    data = urllib.parse.urlencode (query)
    request = urllib.request.Request (url, data.encode ('utf-8'))

    # Execute the query
    try:
      response = urllib.request.urlopen (request)
    except urllib.error.HTTPError as error:
      logging.error ('ERROR: %s' % error.read ().decode ('UTF-8'))
      sys.exit (1)

    data = response.add_results ().decode ('UTF-8').split ('\n')[:-1]

    for record in data:
      json_obj = json.loads (record, object_hook=from_json)
      filename = os.path.split (json_obj.file)[-1]
      function = json_obj.method
      line = 0 # We don't get line numbers from the Klocwork API
      checker = json_obj.code

      if not filename in suite.files:
        suite[filename] = File (filename)

      if not function in suite[filename].functions:
        suite[filename][function] = Function (function)

      if not line in suite[filename][function].lines:
        suite[filename][function][line] = Line (line)

      suite[filename][function][line].add_Bug (Bug (checker))

    logging.info ('Found [%s] bugs for suite [%s]' % (len (suite.get_Bugs ()), suite.directory))

  # @}

  # {@ Analyze hooks

  #
  # Supports granularity
  #
  def supports_granularity (self, granularity):
    if granularity == Granularity.LINE:
      return False
    return True

  # @}
