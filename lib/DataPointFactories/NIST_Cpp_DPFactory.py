#!/bin/env python

from ..DataAbstractions import *
from ..DynamicLoader import DynamicLoader
from .. import Utilities

from collections import defaultdict

import re
import logging
import sys
import os

class NIST_Cpp_DPFactory:
  @staticmethod
  def name ():
    return 'NIST_Cpp'

  def __init__ (self, merged_rs):
    self.needs_min_max = Utilities.needs_min_max (merged_rs)
    self.resultset = merged_rs
    self.tools = self.get_tools (merged_rs)
    self.incidental_cwe_re = re.compile ('CWE\D*(\d+)\D*.*')
    self.permutation_re = re.compile ('.*(\d\d).*')

  def generate (self, granularity, wrong_checker_is_fp, minimum):
    for node in self.iterate_resultset (granularity):
      (tp, fp, fn) = self.compute_probability (node, wrong_checker_is_fp, minimum)

      # If we have nothing to report for this datapoint, skip it.
      if (tp, fp, fn) == (0, 0, 0):
        continue

      (filename, function, line_no) = self.get_location (node, granularity)
      permutation = self.find_permutation (node)

      yield DataPoint (tp,
                       fp,
                       fn,
                       node.get_Weakness ().name,
                       node.get_Suite ().directory,
                       filename,
                       function,
                       line_no,
                       permutation)

  def iterate_resultset (self, granularity):
    for file in self.resultset.iterate_Files ():

      if granularity == Granularity.Filename:
        yield file
      elif granularity == Granularity.Function:
        yield from file.iterate_Functions ()
      else:
        yield from file.iterate_Lines ()

  def get_location (self, node, granularity):
    filename = node.get_File ().filename

    if granularity != Granularity.Filename:
      function = node.get_Function ().function
    else:
      function = ''

    if granularity == Granularity.Line:
      line = node.line
    else:
      line = 0

    return (filename, function, line)

  def compute_probability (self, node, wrong_checker_is_fp, minimum):
    (right_checker_locations, wrong_checker_count) = self.identify_checkers (node)

    tp = 0
    fp = 0
    fn = 0
    expected = 0

    # Do incorrect checkers count as FPs?
    if wrong_checker_is_fp:
      fp += wrong_checker_count

    # If we have function information available, TPs in 'good' functions
    # count as FPs
    if (not isinstance (node, File)) and ('good' in node.get_Function ().function):
      fp += sum ([len (x) for x in right_checker_locations.values ()])
    else:
      # Otherwise, we are either in a 'bad' function or at the File granularity, so
      # the right checkers are TPs.

      # If we have multiple tools, we need to remove duplicate TPs
      if len (self.tools) > 1:
        self.remove_duplicates (right_checker_locations)

      # If we need to apply the min/max criteria due to a tool not supporting reporting
      # by line number, do so.  If we are at the line granularity, then there's no need
      # in doing the min/max since all results from the tool that doesn't support line
      # numbers will be FPs (0 expected at line 0).
      if self.needs_min_max and not isinstance (node, Line) and minimum:
        # Minimum is the smallest number of TPs we can guarantee will be found (maximum overlap)
        tp += max (self.tp_per_tool (right_checker_locations))
      elif self.needs_min_max and not isinstance (node, Line) and not minimum:
        # Maximum is the largest number of TPs we could find (minimum overlap)
        tp += sum (self.tp_per_tool (right_checker_locations))
      else:
        tp += sum ([len (x) for x in right_checker_locations.values ()])

      # We also need to calculate the expected number of flaws, which is any flaw at the
      # current location that is not a fix or incidental
      expected = len ([f for f in node.iterate_Flaws () if not f.severity in [FlawType.Fix, FlawType.Incidental]])

    # If we have more TPs than expected, the extras are FPs
    if tp > expected:
      fp += tp - expected
      tp = expected
    else:
      # We have fewer TPs than expected.  The missing TPs are FNs.
      fn = expected - tp

    return (tp, fp, fn)

  def identify_checkers (self, node):
    right_checker = defaultdict (list)
    wrong_checker = 0
    incidental_cwes = self.identify_incidental_cwes (node)

    for bug in node.iterate_Bugs ():
      tool = self.tools[bug.source]

      if tool.correct_checker (bug, node.get_Weakness ().name):
        right_checker[bug.get_Line ().line].append (bug)
      else:
        # Check if we have the right checker for an incidental flaw
        found_incidental = False
        for cwe in incidental_cwes:
          if tool.correct_checker (bug, cwe):
            found_incidental = True
            break

        if not found_incidental:
          wrong_checker += 1

    return (right_checker, wrong_checker)

  def identify_incidental_cwes (self, node):
    incidental_cwes = set ()

    for flaw in node.iterate_Flaws ():
      if flaw.severity != FlawType.Incidental:
        continue

      match = self.incidental_cwe_re.match (flaw.description)
      if match:
        incidental_cwes.add ('CWE%s' % match.group (1))

    return incidental_cwes

  def tp_per_tool (self, locations):
    # If a tool supports line numbers, merge its TP count with
    # other tools that support line numbers.  These are unique
    # TPs because we have removed duplicates
    results = defaultdict (int)

    # Initalize the results with 0 so if there are no bugs we
    # still return a valid sequence
    results['default'] = 0

    for bugs in locations.values ():
      for bug in bugs:
        if self.tools[bug.source].supports_granularity (Granularity.Line):
          results['multitool'] += 1
        else:
          results[bug.source] += 1

    return results.values ()

  def remove_duplicates (self, locations):
    for (line, bugs) in locations.items ():
      if line == 0:
        # We don't remove duplicates for tools that don't report
        # line numbers because we are unsure of their location
        continue

      if len (bugs) > 1:
        # We have multiple TPs on the same line. Remove any extras
        del bugs[1:]

  def get_tools (self, merged_rs):
    result = {}

    toolLoader = DynamicLoader (os.path.dirname (os.path.abspath(sys.argv[0])), 'lib/Tools')
    toolLoader.loadClasses()

    # Let the Tools modify the parser
    for tool in toolLoader.getClasses ():
      name = tool.name ()

      if name in merged_rs.builds:
        result[name] = tool

    return result

  def find_permutation (self, node):
    filename = node.get_File ().filename

    match = self.permutation_re.match (filename)

    if not match:
      logging.warning ('Unable to extract permutation for [%s]' % filename)
      return

    return match.group (1)
