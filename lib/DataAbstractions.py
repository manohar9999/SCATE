#!/bin/env python

import os
import logging

from os import path

from enum import Enum

def str_to_boolean (s):
  if s == 'True':
    return True
  elif s == 'False':
    return False
  else:
    raise ValueError;

#
# @class ResultSet
#
# The ResultSet is the binary representation of the results from a static
# code analysis tool. The hierarchy of the ResultSet is as follows:
#
# - ResultSet
# -- Weakness
# --- Suite
# ---- File
# ----- Flaw
#
class ResultSet:
  #
  # Factory method
  #
  @staticmethod
  def from_xml (xml):
    return ResultSet (None, xml.get ('source'), xml.get ('args'))

  def __init__ (self, name = None, source = None, args = ''):
    self.name = name
    self.source = source
    self.args = args
    self.weaknesses = {}
    self.builds = {}
    self.imports = {}

  #
  # Overloads to support indexing [] operator
  #
  def __getitem__ (self, key):
    return self.weaknesses[key]

  def __setitem__ (self, key, value):
    self.weaknesses[key] = value

  def __delitem__ (self, key):
    del self.weaknesses[key]

  def iterate_Weaknesses (self):
    yield from self.weaknesses.values ()

  def get_weakness (self, name):
    if name in self.weaknesses:
      return self.weaknesses[name]

    # Create a new weakness and return it to the client.
    weakness = Weakness (self, name)
    self.weaknesses[name] = weakness

    return weakness

  def get_Weaknesses (self):
    return [x for x in self.iterate_Weaknesses ()]

  def iterate_Suites (self):
    for weakness in self.iterate_Weaknesses ():
      yield from weakness.iterate_Suites ()

  def get_Suites (self):
    return [x for x in self.iterate_Suites ()]

  def iterate_Files (self):
    for suite in self.iterate_Suites ():
      yield from suite.iterate_Files ()

  def get_Files (self):
    return [x for x in self.iterate_Files ()]

  def iterate_Functions (self):
    for file in self.iterate_Files ():
      yield from file.iterate_Functions ()

  def get_Functions (self):
    return [x for x in self.iterate_Functions ()]

  def iterate_Lines (self):
    for func in self.iterate_Functions ():
      yield from func.iterate_Lines ()

  def get_Lines (self):
    return [x for x in self.iterate_Lines ()]

  def iterate_Flaws (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Flaws ()

  def get_Flaws (self):
    return [x for x in self.iterate_Flaws ()]

  def iterate_Bugs (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Bugs ()

  def get_Bugs (self):
    return [x for x in self.iterate_Bugs ()]

  def get_ResultSet (self):
    return self

#
# Class Weakness contains Implementation
#
class Weakness:
  #
  # Factory method
  #
  @staticmethod
  def from_xml (xml, parent):
    return Weakness (parent, xml.get ('id'))

  def __init__ (self, parent, name):
    self.name = name
    self.result_set = parent
    self.suites = {}

  #
  # Overloads to support indexing [] operator
  #
  def __getitem__ (self, key):
    return self.suites[key]

  def __setitem__ (self, key, value):
    self.suites[key] = value

  def __delitem__ (self, key):
    del self.suites[key]

  def iterate_Suites (self):
    yield from self.suites.values ()

  def get_suite (self, name, compiler, args):
    if name in self.suites:
      return self.suites[name]

    suite = Suite (self, name, compiler, args)
    self.suites[name] = suite

    return suite

  def get_Suites (self):
    return [x for x in self.iterate_Suites ()]

  def iterate_Files (self):
    for suite in self.iterate_Suites ():
      yield from suite.iterate_Files ()

  def get_Files (self):
    return [x for x in self.iterate_Files ()]

  def iterate_Functions (self):
    for file in self.iterate_Files ():
      yield from file.iterate_Functions ()

  def get_Functions (self):
    return [x for x in self.iterate_Functions ()]

  def iterate_Lines (self):
    for func in self.iterate_Functions ():
      yield from func.iterate_Lines ()

  def get_Lines (self):
    return [x for x in self.iterate_Lines ()]

  def iterate_Flaws (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Flaws ()

  def get_Flaws (self):
    return [x for x in self.iterate_Flaws ()]

  def iterate_Bugs (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Bugs ()

  def get_Bugs (self):
    return [x for x in self.iterate_Bugs ()]

  def get_Weakness (self):
    return self

  def get_ResultSet (self):
    return self.result_set

#
# @class Suite
#
# Collection of \a Flaw elements
#
class Suite:
  #
  # Factory method
  #
  @staticmethod
  def from_xml (xml, parent):
    return Suite (parent,
                  xml.get ('dir'),
                  xml.get ('tool'),
                  xml.get ('args'))

  def __init__ (self, weakness, directory, compiler, args):
    self.weakness = weakness
    self.directory = directory
    self.compiler = compiler
    self.args = args
    self.files = {}

  #
  # Overloads to support indexing [] operator
  #
  def __getitem__ (self, key):
    return self.files[key]

  def __setitem__ (self, key, value):
    self.files[key] = value

  def __delitem__ (self, key):
    del self.files[key]

  def iterate_Files (self):
    yield from self.files.values ()

  def get_file (self, filename):
    if filename in self.files:
      return self.files[filename]

    file = File (self, filename)
    self.files[filename] = file

    return file

  def get_Files (self):
    return [x for x in self.iterate_Files ()]

  def iterate_Functions (self):
    for file in self.iterate_Files ():
      yield from file.iterate_Functions ()

  def get_Functions (self):
    return [x for x in self.iterate_Functions ()]

  def iterate_Lines (self):
    for func in self.iterate_Functions ():
      yield from func.iterate_Lines ()

  def get_Lines (self):
    return [x for x in self.iterate_Lines ()]

  def iterate_Flaws (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Flaws ()

  def get_Flaws (self):
    return [x for x in self.iterate_Flaws ()]

  def iterate_Bugs (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Bugs ()

  def get_Bugs (self):
    return [x for x in self.iterate_Bugs ()]

  def get_Suite (self):
    return self

  def get_Weakness (self):
    return self.weakness

  def get_ResultSet (self):
    return self.weakness.result_set

#
# @class File
#
class File:
  #
  # Factory method for creating a File object from an xml document
  #
  @staticmethod
  def from_xml (xml, parent):
    if xml.get ('file'):
      return File (parent, xml.get ('file'))
    else:
      return File (parent, xml.get ('filename'))

  def __init__ (self, suite, filename):
    self.suite = suite
    self.filename = filename
    self.functions = {}

  def computeFullPath (self):
    return path.join (self.suite.directory, self.filename)

  #
  # Overloads to support indexing [] operator
  #
  def __getitem__ (self, key):
    return self.functions[key]

  def __setitem__ (self, key, value):
    self.functions[key] = value

  def __delitem__ (self, key):
    del self.functions[key]

  def accept (self, visitor):
    visitor.visit_File (self)

  def iterate_Functions (self):
    yield from self.functions.values ()

  def get_function (self, name):
    if name in self.functions:
      return self.functions[name]

    function = Function (self, name)
    self.functions[name] = function

    return function

  def get_Functions (self):
    return [x for x in self.iterate_Functions ()]

  def iterate_Lines (self):
    for func in self.iterate_Functions ():
      yield from func.iterate_Lines ()

  def get_Lines (self):
    return [x for x in self.iterate_Lines ()]

  def iterate_Flaws (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Flaws ()

  def get_Flaws (self):
    return [x for x in self.iterate_Flaws ()]

  def iterate_Bugs (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Bugs ()

  def get_Bugs (self):
    return [x for x in self.iterate_Bugs ()]

  def get_File (self):
    return self

  def get_Suite (self):
    return self.suite

  def get_Weakness (self):
    return self.suite.weakness

  def get_ResultSet (self):
    return self.suite.weakness.result_set

#
# @class Function
#
class Function:
  #
  # Factory method
  #
  @staticmethod
  def from_xml (xml, parent):
    return Function (parent, xml.get ('function'))

  def __init__ (self, file, name):
    self.file = file
    self.function = name
    self.lines = {}

  #
  # Overloads to support indexing [] operator
  #
  def __getitem__ (self, key):
    return self.lines[key]

  def __setitem__ (self, key, value):
    self.lines[key] = value

  def __delitem__ (self, key):
    del self.lines[key]

  def accept (self, visitor):
    visitor.visit_Function (self)

  def iterate_Lines (self):
    yield from self.lines.values ()

  def get_line (self, lineno):
    if lineno in self.lines:
      return self.lines[lineno]

    line = Line (self, lineno)
    self.lines[lineno] = line

    return line

  def get_Lines (self):
    return [x for x in self.iterate_Lines ()]

  def iterate_Flaws (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Flaws ()

  def get_Flaws (self):
    return [x for x in self.iterate_Flaws ()]

  def iterate_Bugs (self):
    for line in self.iterate_Lines ():
      yield from line.iterate_Bugs ()

  def get_Bugs (self):
    return [x for x in self.iterate_Bugs ()]

  def get_Function (self):
    return self

  def get_File (self):
    return self.file

  def get_Suite (self):
    return self.file.suite

  def get_Weakness (self):
    return self.file.suite.weakness

  def get_ResultSet (self):
    return self.file.suite.weakness.result_set

#
# @class Line
#
class Line:
  #
  # Factory method
  #
  @staticmethod
  def from_xml (xml, parent):
    return Line (parent, int (xml.get ('line')))

  def __init__ (self, function, line = 0):
    self.function = function
    self.line = line
    self.bugs = []
    self.flaws = []

  def accept (self, visitor):
    visitor.visit_Line (self)

  def add_Flaw (self, flaw):
    self.flaws.append (flaw)

  def add_Bug (self, bug):
    self.bugs.append (bug)

  def iterate_Flaws (self):
    yield from self.flaws

  def add_flaw (self, severity, description, source):
    flaw = Flaw (self, severity, description, source)
    self.flaws.append (flaw)

    return flaw

  def get_Flaws (self):
    return [x for x in self.iterate_Flaws ()]

  def iterate_Bugs (self):
    yield from self.bugs

  def get_Bugs (self):
    return [x for x in self.iterate_Bugs ()]

  def get_Line (self):
    return self

  def get_Function (self):
    return self.function

  def get_File (self):
    return self.function.file

  def get_Suite (self):
    return self.function.file.suite

  def get_Weakness (self):
    return self.function.file.suite.weakness

  def get_ResultSet (self):
    return self.function.file.suite.weakness.result_set

#
# @class FlawType
#
# Enumerations of the different flaw types.
#
class FlawType (Enum) :
  Unknown = 0
  Flaw = 1
  Potential = 2
  Incidental = 3
  Fix = 4

#
# @class Flaw
#
# Wrapper class for the flaw definition.
#
class Flaw:
  #
  # Factory method for creating a Flaw object from a \a xml document.
  #
  @staticmethod
  def from_xml (xml, parent, source) :
    from html import unescape

    return Flaw (parent,
                 FlawType [xml.get ('severity')],
                 unescape (xml.get ('description')),
                 source)
  
  def __init__ (self, line, severity, description, source):
    self.line = line
    self.severity = severity
    self.description = description
    self.source = source

  def __eq__ (self, rhs):
    return (self.severity == rhs.severity) and \
           (self.description == rhs.description) and \
           (self.source == rhs.source)

  def get_Line (self):
    return self.line

  def get_Function (self):
    return self.line.function

  def get_File (self):
    return self.line.function.file

  def get_Suite (self):
    return self.line.function.file.suite

  def get_Weakness (self):
    return self.line.function.file.suite.weakness

  def get_ResultSet (self):
    return self.line.function.file.suite.weakness.result_set

 
#
# @class Bug
# 
# A Bug is a single result from running a build. This class is used for 
# analysis purposes. Probability_info can be any string necessary for a 
# \a Tool to identify the result from the Bug.
#
class Bug:
  #
  # Factory method for creating a Bug object from a \a xml document.
  #
  @staticmethod
  def from_xml (xml, source):
    from html import unescape

    return Bug (xml.get ('type'),
                source,
                unescape (xml.get ('message')))

  def __init__ (self, type, source, message = None):
    self.type = type
    self.source = source
    self.line = None
    self.message = message

  def get_Line (self):
    return self.line

  def get_Function (self):
    return self.line.function

  def get_File (self):
    return self.line.function.file

  def get_Suite (self):
    return self.line.function.file.suite

  def get_Weakness (self):
    return self.line.function.file.suite.weakness

  def get_ResultSet (self):
    return self.line.function.file.suite.weakness.result_set

  def get_ErrorMessage (self):
    return self.message

#
# @class Granularity
#
# Enumerations of the different granularities.
# These are used to define what information a tool
# can return as well as how reporting should be handled
#
class Granularity (Enum) :
  Unknown = 0
  Filename = 1
  Function = 2
  Line = 3

#
# @class DataPointSet
#
# A basic class to aggregate DataPoints.  Includes
# import and build information for reporting purposes
#
class DataPointSet:
  @staticmethod
  def from_xml (xml):
    return DataPointSet ()

  def __init__ (self):
    self.imports = {}
    self.builds = {}
    self.criterias = {}

  def __getitem__ (self, key):
    return self.criterias[key]

  def __setitem__ (self, key, value):
    self.criterias[key] = value

  def __delitem__ (self, key):
    del self.criterias[key]

  def iterate_Criterias (self):
    yield from self.criterias.values ()

  def get_Criterias (self):
    return [x for x in self.iterate_Criterias ()]

  def iterate_DataPoints (self):
    for criteria in iterate_Criterias:
      yield from critera.get_DataPoints ()

  def get_DataPoints (self):
    return [x for x in self.iterate_DataPoints ()]

#
# @class DataPoint_Criteria
#
# A class which aggregates DataPoints and has
# criteria information that was used to create the
# DataPoints (i.e. granularity)
#
class DataPointCriteria:
  @staticmethod
  def from_xml (xml):
    return DataPointCriteria (Granularity [xml.get ('granularity')],
                              str_to_boolean (xml.get ('wrong_checker_is_fp')),
                              str_to_boolean (xml.get ('minimum')))

  def __init__ (self, granularity, wrong_checker_is_fp, minimum):
    self.datapointset = None
    self.granularity = granularity
    self.wrong_checker_is_fp = wrong_checker_is_fp
    self.minimum = minimum
    self.datapoints  = []

  def iterate_DataPoints (self):
    yield from self.datapoints

  def get_DataPoints (self):
    return datapoints

  def get_DataPointSet (self):
    return self.datapointset

#
# @class DataPoint
#
# Results class to be used by ReportGenerators.  Datapoints
# are created by comparing build results against the import
# information
#
class DataPoint:
  @staticmethod
  def from_xml (xml):
    return DataPoint (int (xml.get ('tp')),
                      int (xml.get ('fp')),
                      int (xml.get ('fn')),
                      xml.get ('weakness'),
                      xml.get ('directory'),
                      xml.get ('filename'),
                      xml.get ('function'),
                      int (xml.get ('line')),
                      xml.get ('permutation'))

  def __init__ (self, tp, fp, fn, weakness, directory, filename, function, line, permutation):
    self.criteria = None
    self.tp = tp
    self.fp = fp
    self.fn = fn
    self.weakness = weakness
    self.directory = directory
    self.filename = filename
    self.function = function
    self.line = line
    self.permutation = permutation

  def get_DataPointCriteria (self):
    return self.criteria

  def get_DataPointSet (self):
    return self.criteria.datapointset
