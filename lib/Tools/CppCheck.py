################################################################################
#
# file : CppCheck.py
#
# author: Enas Alikhashashneh <ealikhas@umail.iu.edu>
#
################################################################################

from ..Tool import Tool
from ..DataAbstractions import File, Function, Line, Bug
from .. import Utilities

import os
import logging
from lxml import objectify

#
# Factory method that creates the CppCheck tool
#
def __create__ ():
  return CppCheck ()

#
# @class CppCheck
#
# Wrapper class for the CppCheck tool
#
class CppCheck (Tool):
  #
  # Default constructor.
  #
  def __init__ (self):
    super (CppCheck, self).__init__ (
        'cppcheck',
        {
          'CWE120' : ['invalidscanf','bufferAccessOutOfBounds','possibleBufferAccessOutOfBounds','insecureCmdLineArgs'],
          'CWE129' : ['arrayIndexThenCheck'],
          'CWE131' : ['mismatchSize', 'sizeofwithnumericparameter', 'sizeofwithsilentarraypointer',
                      'sizeofsizeof', 'sizeofCalculation'],
          'CWE170' : ['terminateStrncpy','bufferNotZeroTerminated','uninitstring'],
          'CWE194' : ['charArrayIndex', 'charBitOp','charArrayIndex','charBitOp'],
          'CWE195' : ['udivError'],
          'CWE253' : ['catchExceptionByValue'],
          'CWE369' : ['zerodiv'],
          'CWE398' : ['duplicateBreak','duplicateIf','duplicateExpression'],
          'CWE401' : ['memleak','memleakOnRealloc','publicAllocationError','leakNoVarFunctionCall'],
          'CWE404' : ['resourceLeak'],
          'CWE415' : ['deallocDealloc'],
          'CWE416' : ['deallocuse'],
          'CWE456' : ['noConstructor','uninitVar','uninitdata', 'uninitvar'],
          'CWE468' : ['strPlusChar'],
          'CWE476' : ['nullPointer'],
          'CWE477' : ['obsoleteFunctions'],
          'CWE484' : ['redundantAssignInSwitch','redundantStrcpyInSwitch', 'switchCaseFallThrough'],
          'CWE561' : ['assignIfError', 'comparisonError', 'multiCondition', 'incorrectLogicOperator',
                      'secondAlwaysTrueFalseWhenFirstTrue','staticStringCompare'],
          'CWE562' : ['returnAddressOfAutoVariable', 'returnLocalVariable', 'autoVariables',
                      'returnAddressOfFunctionParameter','returnReference', 'returnTempReference',
                      'returnAutocstr', 'returnTempPointer'],
          'CWE571' : ['incorrectStringBooleanError','stringCompare','unsignedPositive'],
          'CWE573' : ['boostForeachError'],
          'CWE587' : ['assignBoolToPointer'],
          'CWE663' : ['nonreentrantFunctions'],
          'CWE665' : ['fflushOnInputStream'],
          'CWE670' : ['comparisonOfBoolWithInt'],
          'CWE676' : ['dangerousUsageStrtol'],
          'CWE686' : ['passedByValue','memsetClass','wrongPrintfScanfArgs'],
          'CWE687' : ['memsetZeroBytes','wrongmathcall','incorrectStringCompare'],
          'CWE704' : ['cstyleCast'],
          'CWE762' : ['mismatchAllocDealloc'],
          'CWE783' : ['clarifyCalculation','clarifyCondition'],
          'CWE786' : ['negativeIndex'],
          'CWE805' : ['possibleReadlinkBufferOverrun','strncatUsage','outOfBounds','sizeArgumentAsChar'],
          'CWE823' : ['arrayIndexOutOfBounds','pointerOutOfBounds'],
          'CWE826' : ['unusedScopedObject'],
          'CWE843' : ['AssignmentAddressToInteger', 'AssignmentIntegerToAddress'],
        }
    )

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    CppCheck_parser = parser.add_parser ('cppcheck', help='use CppCheck as the build tool')
    CppCheck_parser.set_defaults (tool=self)
    
  # Handle compiling a suite
  def handle_compile (self, suite):
    logging.info ('Compiling suite [%s] with tool [%s]' % (suite.directory, self.name ()))

    # Get into the correct directory
    suite_abspath = os.path.abspath (os.path.join (self.__SCATE_root__, suite.directory))
    logging.info ('Running CppCheck (may take some time) ...')

    cmd = ['cppcheck',
           '--inconclusive',
           '--xml-version=2',
           '-j',
           '4',
           suite_abspath]

    with open ('errors.xml', 'w') as outfile:
      Utilities.run_cmd (cmd, stderr=outfile)

  #
  # Generate the result set for the output produced during the compile
  # phase of the build process.
  #
  def handle_docgen (self, suite):
    results = objectify.parse ('errors.xml')
    root = results.getroot ()

    from os.path import basename

    for errors in root.iter ('errors'):
      for error in errors.iter ('error'):
        message = error.get ('msg')

        for location in error.iter ('location'):
          filename = location.get ('file')
          lineno = location.get ('line')

          function = ''

          if not filename in suite.files:
            suite[filename] = File(suite, os.path.relpath(filename, start=suite.directory))

          if not function in suite[filename].functions:
            suite[filename][function] = Function(os.path.relpath(filename, start=suite.directory), function)

          if not lineno in suite[filename][function].lines:
              suite [filename] [function] [lineno] = Line (function, lineno)

          suite[filename][function][lineno].add_Bug (Bug (error.get ('id'), self.name (), message))

    logging.info ('Found [%s] bugs for suite [%s]' % (len (suite.get_Bugs ()), suite.directory))

