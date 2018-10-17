#!/bin/env python

################################################################################
#
# file : JulietJavaParser.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################

from ..DataAbstractions import ResultSet, Weakness, Suite, Flaw
from ..ImportSuite import ImportSuite
from .. import Utilities

from pyparsing import *
import os
import logging

#
# Factory Method for Test Suites
#
def __create__():
  return JulietJavaParser()

#
# Worker function for multithreaded imports
#
def run_worker (directory, filename):
  parser = JulietJavaParser ()
  return parser.parse (directory, filename)

#
#concrete class - NistSuite
#
class JulietJavaParser (ImportSuite):

  #
  # Constructor
  #
  def __init__(self):
    super (JulietJavaParser, self).__init__ ('JulietJava')

    self.targets_ = []
    self.__current_suite__ = None

  #
  # Initialize the parser
  #
  def init_parser (self, parser):
    juliet_java_parser = parser.add_parser (self.getSource (), help='Use the NIST Juliet Java Suite')
    juliet_java_parser.set_defaults (suite=self)

  #
  # Initalize the suite
  #
  def parse_args (self, args):
    # Call the base class (Command) init
    super (JulietJavaParser, self).parse_args (args)

    # @TODO: Remove hardcoded paths
    self.__SCATE_root__ = os.path.realpath (os.path.join (os.path.dirname (__file__), '../../'))
    self.__NIST_root__ = os.path.realpath (os.path.join (self.__SCATE_root__, 'test-cases/NIST_Java/'))
    self.__testcase_dir__ = os.path.realpath (os.path.join (self.__NIST_root__, 'src/testcases'))

    #
    # Defining Grammar which detects function having flaw in their body
    #
    # 'Alphanums' are both Alphabets and Numbers
    # 'Literals' searches for only particular strings, or words or letters
    # '+' is defined as or inside braces -> refer to function_name  and 'and' outside braces -> refer to function decl
    #

    # Detects int,float etc and whcar_t return types
    returntype = Word(alphas+'_')
    accessmodifiers = Word(alphas)
    function_name= Word(alphanums+'_')
    method_name= Word(alphanums+'_')
    args= Word(alphanums+'_'+'*'+'&'+'<'+'>'+'['+']'+',')
    function_open = Literal("{")
    function_close = Literal("}")
    exception = Literal("throws Throwable")
    ioexception = Literal("throws IOException")
    comment_open=Literal("/*")
    comment_close = Literal("*/")
    comments=comment_open+OneOrMore(Word(alphas+'*'+':'+','+'.'))
    self._name_space=Literal("namespace")+Word(alphanums+'_')

    # Searches flaw in function body and then skips to comment_close which is defined above
    # This searches only for FLAW's not POTENTIAL FLAW
    #self._function_body_with_flaw=Literal("/* FLAW:")+SkipTo(comment_close)+comment_close+(Optional(OneOrMore(comments+SkipTo(comment_close))))+Optional(comment_close)+Optional(Word(alphanums+';'+'('+')'+'<'+'>'+'!'))

    self._function_body_with_flaw= Literal("/* FLAW:")+SkipTo(comment_close)+comment_close+(Optional(OneOrMore(comments+SkipTo(comment_close)+comment_close)))

    # This searches only for POTENTIAL FLAW's
    self._function_body_with_potential_flaw=Literal("/* POTENTIAL FLAW:")+SkipTo(comment_close)+comment_close+(Optional(OneOrMore(comments+SkipTo(comment_close))))+Optional(comment_close)+Optional(Word(alphanums+';'+'('+')'+'<'+'>'+'!'))

    # This searches only for INCIDENTAL FLAW's
    self._function_body_with_incidental_flaw=Literal("/* INCIDENTAL:")+SkipTo(comment_close)+comment_close+(Optional(OneOrMore(comments+SkipTo(comment_close))))+Optional(comment_close)+Optional(Word(alphanums+';'+'('+')'+'<'+'>'+'!'))

    # This searches only for FIX's
    self._function_body_with_fix=Literal("FIX:")+SkipTo(comment_close)+comment_close+(Optional(OneOrMore(comments+SkipTo(comment_close))))+Optional(comment_close)+Optional(Word(alphanums+';'+'('+')'+'<'+'>'+'!'))

    # Matches the function declaration both C and CPP in namespaces
    self.function_decl=Optional(accessmodifiers)+Optional("static")+Optional("const")+returntype+Optional("*")+Optional(OneOrMore(function_name)+'::')+function_name.setResultsName("function")+"("+Optional(OneOrMore(args))+")"+Optional(exception)+Optional(ioexception)+Optional("const")

    #function_decl = Optional(accessmodifiers)+Optional(namespace.setResultsName("name_space"))+Optional("static")+Optional("const")+returntype+Optional("*")+function_name.setResultsName("cfunction")+Optional(javafunctionname).setResultsName("javafunc")+Optional("::")+Optional(method_name).setResultsName("cppmethod")+"("+Optional(OneOrMore(args))+")"+Optional(exception)+Optional("const")

    # Matches the outer braces of a function
    detectflawbody = MatchFirst(nestedExpr ('{', '}'))

    # funcloc contains position of where the function declaration ends
    self._funloc=0


    # Combining grammar for function declaration and to detect flawbody
    self._grammar_with_flaw = Optional(self._function_body_with_flaw.setResultsName("flaw_before_function"))+self.function_decl.setResultsName("funcdec")+Optional(originalTextFor(detectflawbody).setResultsName("body"))

    self._grammar_with_potential_flaw = Optional(self._function_body_with_potential_flaw.setResultsName("poten_flaw_before_function"))+self.function_decl.setResultsName("funcdec")+originalTextFor(detectflawbody).setResultsName("body")

    self._grammar_with_incidental_flaw = Optional(self._function_body_with_incidental_flaw.setResultsName("inci_flaw_before_function"))+self.function_decl.setResultsName("funcdec")+originalTextFor(detectflawbody).setResultsName("body")

    self._grammar_with_fix = Optional(self._function_body_with_fix.setResultsName("keyword_before_fix"))+self.function_decl.setResultsName("funcdec")+originalTextFor(detectflawbody).setResultsName("body")

    #calling printloc function to get funloc
    detectflawbody.setParseAction(self.printloc)

  #
  # Default elements passed when ParseAction is called are st,locn,toks
  #
  def printloc (self,st,locn,toks):
    self._funloc =  locn
    #print "printloc: %d" % (funloc)#, repr(st), repr(toks))

  #
  # Parses the file and handles the weakness obj accordingly
  # Contains the parse logic which uses grammar in __init__
  #
  def parse (self, directory, filename):
    logging.info ('Importing file [%s]' % filename)
    results = []

    full_path = os.path.join (directory, filename)
    fileptr = open (full_path, 'r')
    filestring = fileptr.read()
    fileptr.close ()

    # Reads each file into filestring and passes in to scanString() which parses it with 'grammar'
    # Get FLAWs
    for token,start,end in self._grammar_with_flaw.scanString(filestring):
          #print "Flaw before error: %s"%(token.flaw_before_function)
          #print "funcdec: %s"%(token.funcdec)
      if(token.flaw_before_function):
            #print "Flaw Before Function.........................."
            #for flawtoken,flawstart,flawend in self._function_body_with_flaw.scanString(token.body):
        if 'function' in token.funcdec:
          #print token.funcdec.function
          results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc,filestring),'3'))
      elif(token.funcdec):
        #print "Flaw in function"
        #print token.body
        for flawtoken,flawstart,flawend in self._function_body_with_flaw.scanString(token.body):
          #print flawtoken,flawstart,flawend
          if 'function' in token.funcdec:
            #print "Insideeeeeeeeeeeeeeeeee %s"%(token.funcdec.function)
            results.append (Flaw(filename,token.funcdec.function,str(lineno(self._funloc+flawend,filestring)),'3'))
      elif(token.name_space_):
        for flawtoken,flawstart,flawend in self._function_body_with_flaw.scanString(token.body):
          if 'function' in token.funcdec:
            results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc+flawend,filestring),'3'))
          else:
            results.append (Flaw(filename,'',lineno(self._funloc+flawend,filestring),'3'))

    # Get POTENTIAL_FLAWs
    for token,start,end in self._grammar_with_potential_flaw.scanString(filestring):
      if(token.poten_flaw_before_function):
        if 'function' in token.funcdec:
          results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc,filestring),'2'))
      elif(token.funcdec):
        for flawtoken,flawstart,flawend in self._function_body_with_potential_flaw.scanString(token.body):
          if 'function' in token.funcdec:
            results.append (Flaw(filename,token.funcdec.function,str(lineno(self._funloc+flawend,filestring)),'2'))
      elif(token.name_space_):
        for flawtoken,flawstart,flawend in self._function_body_with_potential_flaw.scanString(token.body):
          if 'function' in token.funcdec:
            results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc+flawend,filestring),'2'))
          else:
            results.append (Flaw(filename,'',lineno(self._funloc+flawend,filestring),'2'))

    # Get INCIDENTAL_FLAWs
    for token,start,end in self._grammar_with_incidental_flaw.scanString(filestring):
      if(token.inci_flaw_before_function):
        if 'function' in token.funcdec:
          results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc,filestring),'1'))
      elif(token.funcdec):
        for flawtoken,flawstart,flawend in self._function_body_with_incidental_flaw.scanString(token.body):
          if 'function' in token.funcdec:
            results.append (Flaw(filename,token.funcdec.function,str(lineno(self._funloc+flawend,filestring)),'1'))
      elif(token.name_space_):
        for flawtoken,flawstart,flawend in self._function_body_with_incidental_flaw.scanString(token.body):
          if 'function' in token.funcdec:
            results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc+flawend,filestring),'1'))
          else:
            results.append (Flaw(filename,'',lineno(self._funloc+flawend,filestring),'1'))

    # Get FIXes
    for token,start,end in self._grammar_with_fix.scanString(filestring):
      if(token.keyword_before_fix):
        if 'function' in token.funcdec:
          results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc,filestring),'0'))
      elif(token.funcdec):
        for flawtoken,flawstart,flawend in self._function_body_with_fix.scanString(token.body):
          if 'function' in token.funcdec:
            results.append (Flaw(filename,token.funcdec.function,str(lineno(self._funloc+flawend,filestring)),'0'))
      elif(token.name_space_):
        for flawtoken,flawstart,flawend in self._function_body_with_fix.scanString(token.body):
          if 'function' in token.funcdec:
            results.append (Flaw(filename,token.funcdec.function,lineno(self._funloc+flawend,filestring),'0'))
          else:
            results.append (Flaw(filename,'',lineno(self._funloc+flawend,filestring),'0'))

    return results

  def HandleJavaResultSet (self, result_set):
    logging.debug ('Java testcase root is [%s]' % self.__testcase_dir__)

    for weakness_name in self.__weaknesses__:
      # If the weakness is already in the result set, delete it
      if (result_set.ContainsWeakness (weakness_name)):
        logging.info ('Found weakness [%s] in result set, deleting old results' % weakness_name)
        result_set.removeweakness (weakness_name)

      # Create the weakness and suite
      weakness = Weakness (weakness_name)
      flaw_count = 0

      # NIST Java can have subdirectories for weaknesses, create a suite for each of them
      for directory in self.get_suite_directories (weakness_name):
        logging.debug ('Found suite directory [%s]' % directory)
        self.__current_suite__ = Suite (os.path.relpath (directory, self.__SCATE_root__), 'ant', 'compile')

        # Multiprocessing pools cannot be reopened after closing,
        # so a pool must be created for each suite
        multithreaded = False
        if self.__threads__ > 1:
          from multiprocessing import Pool
          logging.debug ('Multithreading enabled, allocting pool with [%s] workers' % self.__threads__)
          pool = Pool (self.__threads__)
          multithreaded = True

        for filename in self.get_files (directory):
          # Dispatch parsing the file
          if multithreaded:
            # @TODO: Pretty lazy implementation of breaking up the work, could be optimized
            pool.apply_async (run_worker, args=(directory, filename), callback=self.handle_flaws)
          else:
            self.handle_flaws (self.parse (directory, filename))

        if multithreaded:
          # Close the pool and execute the work
          pool.close ()
          pool.join ()

        # Attach the suite to the weakness
        flaw_count += self.__current_suite__.GetCount ()
        weakness.add (self.__current_suite__)

      # All suites are attached, now attach the weakness to the result set
      logging.debug ('Imported [%d] flaws into weakness [%s]' % (flaw_count, weakness_name))
      result_set.add (weakness)

  #
  # Identify suite directories for the provided weakness
  #
  def get_suite_directories (self, weakness_name):
    # Directory structures:
    # CWE[#]_[NAME]/
    # CWE[#]_[NAME]/s[#]
    for weakness in os.listdir (self.__testcase_dir__):
      if weakness.startswith (weakness_name):
        files = os.listdir (os.path.join (self.__testcase_dir__, weakness))

        # single directory, CWE[#]_[NAME]/
        if 'build.xml' in files:
          return [os.path.join (self.__testcase_dir__, weakness)]

        # multiple directories, CWE[#]_[NAME]/s[#]
        return [os.path.join (self.__testcase_dir__, weakness, subdir) for subdir in files]

    logging.error ('Error: Suite directories not found for [%s]' % weakness_name)

  #
  # Get the files to parse in the provided directory
  #
  def get_files (self, directory):
    results = []
    for filename in os.listdir (directory):
      if filename.endswith ('.java') and 'Main' not in filename:
        results.append (filename)

    return results

  #
  # Append the provided list of flaws to the current suite
  #
  def handle_flaws (self, flaws):
    for flaw in flaws:
      self.__current_suite__.add (flaw)

  #
  # Main entry point for import commands.  This should result in
  # populating the result set.
  #
  def import_testcases (self, result_set):
    if not self.__weaknesses__:
      logging.info ('No weaknesses provided, importing all weaknesses')
      self.__weaknesses__ = self.get_all_weaknesses ()
      logging.debug ('Found weaknesses [%s]' % self.__weaknesses__)

    self.HandleJavaResultSet (result_set)

  #
  # Gets all the weaknesses
  #
  def get_all_weaknesses(self):
    # Directory structure: CWE[#]_[NAME].  Directory also has extra 'common'
    results = []
    for directory in os.listdir (self.__testcase_dir__):
      if directory.startswith ('CWE'):
        results.append (directory.split ('_')[0])
