from ..ReportGenerator import ReportGenerator
from ..DataAbstractions import ResultSet, Weakness, Suite, Flaw, FlawType, Bug
from .. import Utilities

import logging
import csv
import sys
from enum import Enum
from collections import defaultdict
import docx
import os
import re

#
# Factory Method for Test Suites
#
def __create__ ():
  return WordGenerator ()

class Organizer:
  class Granularity (Enum) :
    FILENAME = 0
    FUNCTION = 1
    LINE = 2

  def __init__ (self, granularity, truth, build):
    self.granularity = granularity
    self.truth_rs = truth
    self.build_rs = build

    # shamelessly stolen from:
    # http://stackoverflow.com/questions/16724788/how-can-i-get-python-to-automatically-create-missing-key-value-pairs-in-a-dictio
    # Recursive dictionary factory, automatically creates directory keys if they do
    # not exist. Default values are dicts. i.e. nested_dict[1][2][3] will automatically
    # create a structure like {1: {2: {3: {}}}
    nested_dict = lambda: defaultdict(nested_dict)
    self.data = nested_dict ()

  def organize (self):
    self._group (self.truth_rs)
    self._group (self.build_rs)

  def _group (self, result_set):
    for weakness in result_set.weaknesses ():
      for suite in weakness.suites:
        # Handle the flaws
        for flaw in suite.flaws:
          # Find the target, this will create the necessary keys if required
          target = self._get_target (weakness, suite, flaw)

          if not target:
            # First time seeing this file/fuction/line, need to set its value
            newdict = self._get_default_data (weakness, suite, flaw)
            target.update (newdict)
          else:
            target['flaws'].append (flaw)

        # Handle the bugs
        for bug in suite.bugs:
          # If the bug is not in a CWE test file (CWE###_...), skip it
          if not bug.filename.startswith ('CWE'):
            continue

          # Find the target, this will create the necessary keys if required
          target = self._get_target (weakness, suite, bug)

          if not target:
            # First time seeing this file/fuction/line, need to set its value
            newdict = self._get_default_data (weakness, suite, bug)
            target.update (newdict)
          else:
            target['bugs'].append (bug)

  #
  # Get the appropriate target based on the granularity
  #
  def _get_target (self, weakness, suite, obj):
    if self.granularity == Organizer.Granularity.FILENAME:
      return self.data[weakness.name][suite.directory][obj.filename]
    elif self.granularity == Organizer.Granularity.FUNCTION:
      return self.data[weakness.name][suite.directory][obj.filename][obj.function]
    else:
      return self.data[weakness.name][suite.directory][obj.filename][obj.function][obj.line]

  #
  # Make the default data dictionary based on the object provided
  #
  def _get_default_data (self, weakness, suite, obj):
    # We always have flaws, bugs, weakness, directory, and filename
    result = {'flaws': [], 'bugs': [], 'weakness': weakness.name, 'directory': suite.directory,
              'filename': obj.filename, 'function': '', 'line': ''}

    # Populate the function/line if we used that granularity
    if self.granularity == Organizer.Granularity.FUNCTION:
      result['function'] = obj.function
    elif self.granularity == Organizer.Granularity.LINE:
      result['function'] = obj.function
      result['line'] = obj.line

    # Append the provided object to the correct list
    if isinstance (obj, Bug):
      result['bugs'].append (obj)
    else:
      result['flaws'].append (obj)

    return result

  #
  # Find the leaves in the provided organized dictionary
  #
  def find_leaves (self, dictionary):
    if isinstance (dictionary.get ('flaws'), list):
      return [dictionary]

    result = []
    for key in dictionary.keys ():
      result.extend (self.find_leaves (dictionary.get (key)))
    return result

class DataPoint:
  def __init__ (self):
    self.tp = 0
    self.fp = 0
    self.fn = 0
    self.weakness = None
    self.directory = None
    self.flaws = []
    self.bugs = []
    self.tool = None
    self.truth = None

  def precision (self):
    try:
      return self.tp / (self.tp + self.fp * 1.0)
    except Exception as e:
      return 0

  def recall (self):
    try:
      return self.tp / (self.tp + self.fn * 1.0)
    except Exception as e:
      return 0

#
# Word Generator
#
class WordGenerator (ReportGenerator):
  #
  # Initialize the parser
  #
  @staticmethod
  def init_parser (parser):
    pt_parser = parser.add_parser ('word', help='Convert evidence into a word document (docx)')
    pt_parser.set_defaults (generator=WordGenerator)
  #
  # Initalize the generator
  #
  def parse_args (self, args):
    # Call the base class (Command) init
    super (WordGenerator, self).parse_args (args)
    self.document = docx.Document ()
    self.pages = []
    self.skip_document = docx.Document ()
    self.skip_pages = []
    self.appendix = None
    self.load_pages ()
    self.incidental_cwe_re = re.compile ('CWE\D*(\d+)\D*.*')

  #
  # Load the pages
  #
  def load_pages (self):
    # Some pages are repeated per granularity (i.e. Summary). These should
    # be in the correct order.
    page_order = ['Methodology', 'Summary', 'Detail', 'HeatMap']

    script_path = os.path.dirname (os.path.abspath (sys.argv[0]))
    for cls in Utilities.import_classes (script_path, 'lib/ReportGenerators/WordPages', 'name'):
      if cls.name () == 'Appendix':
        self.appendix = cls ()
      elif cls.name () in page_order:
        self.pages.insert (page_order.index (cls.name ()), cls ())
        self.skip_pages.insert (page_order.index (cls.name ()), cls())
      else:
        logging.warning ("WARNING: Found unexpected Word Page [%s], skipping..." % cls.name ())
 
    logging.debug ('Loaded WordPages [%s]' % self.pages)

  #
  # Generate Report of respective type
  #
  def generate (self, truth, build):
    # Construct the appropriate Tool object which was used for the build
    self.tool = self.get_tool (build)()

    self.init_doc (build.GetSource (), truth.GetSource ())
    self.appendix.parse_args ()

    logging.info ('Generating report based on filename')
    self.write_report (truth, build, Organizer.Granularity.FILENAME)
    logging.info ('Generating report based on function')
    self.write_report (truth, build, Organizer.Granularity.FUNCTION)
    logging.info ('Generating report based on line')
    self.write_report (truth, build, Organizer.Granularity.LINE)

    # Finialize the pages
    for page in self.pages:
      page.fini (self.document)

    for page in self.skip_pages:
      page.fini (self.skip_document)

    self.appendix.fini (self.document)
    self.appendix.fini (self.skip_document)


    self.document.save ('%s.docx' % build.GetSource ())
    self.skip_document.save ('%s.skip.docx' % build.GetSource ())

  def write_report (self, truth, build, granularity):
    # Organize the truth and build result sets
    organizer = Organizer (granularity,
                           truth,
                           build)
    organizer.organize ()

    # Initalize the pages
    for page in self.pages:
      page.parse_args (organizer, True)

    for page in self.skip_pages:
      page.parse_args (organizer, False)

    # Get the leaves
    for data in organizer.find_leaves (organizer.data):
      # Build datapoint
      datapoint = self.build_datapoint (organizer, data, True)
      skip_datapoint = self.build_datapoint (organizer, data, False)

      self.appendix.visit (datapoint)
      for page in self.pages:
        page.visit (datapoint)

      for page in self.skip_pages:
        page.visit (skip_datapoint)

  #
  # Build a datapoint from the provided data structure
  #
  def build_datapoint (self, organizer, data, wrong_checker_is_fp):
    # Get the probability matrix
    (tp, fp, fn) = self.compute_probability (data, wrong_checker_is_fp)

    # Build a data point
    result = DataPoint ()
    result.tp = tp
    result.fp = fp
    result.fn = fn
    result.weakness = data['weakness']
    result.directory = data['directory']
    result.flaws = data['flaws']
    result.bugs = data['bugs']
    result.tool = organizer.build_rs.GetName ()
    result.truth = organizer.truth_rs.GetName ()
    return result

  #
  # Compute the probability matrix from the provided data
  #
  def compute_probability (self, data, wrong_checker_is_fp):
    # Build a list of incidental CWEs which appear in the data
    incidentals = [f for f in data['flaws'] if f.severity == FlawType.INCIDENTAL]

    incidental_cwes = set ()
    for flaw in incidentals:
      match = self.incidental_cwe_re.match (flaw.description)
      if match:
        incidental_cwes.add ('CWE%s' % match.group (1))

    right_checker = 0
    wrong_checker = 0

    # Check the bugs to see if they have the right or wrong checker
    for bug in data['bugs']:
      if self.tool.correct_checker (bug, data['weakness']):
        right_checker += 1
      else:
        # Check for true positives on incidental flaws
        found_incidental = False
        for cwe in incidental_cwes:
          if self.tool.correct_checker (bug, cwe):
            found_incidental = True

        if not found_incidental:
          wrong_checker += 1

    # Compute the TP/FP/FN probability matrix
    tp = 0
    fp = 0
    fn = 0
    expected = 0

    if wrong_checker_is_fp:
      fp += wrong_checker

    # Correct checkers in good functions are false positives
    if 'good' in data['function']:
      fp += right_checker
    else:
      tp += right_checker
      # Since we are in a bad function, figure out how many flaws were expected
      expected = len ([f for f in data['flaws'] if f.severity != FlawType.FIX
                       and f.severity != FlawType.INCIDENTAL])

    if tp > expected:
      fp += tp - expected
      tp = expected
    else:
      # The tool didn't find some of the expected flaws
      fn = expected - tp

    return (tp, fp, fn)

  #
  # Write the generic portion of the latex report
  #
  def init_doc (self, tool_name, truth_name):
    self.document.add_heading ('SCATE Report for %s Against %s' % (tool_name, truth_name), 0)
    self.document.add_page_break ()

    self.skip_document.add_heading ('SCATE Report for %s Against %s (skip)' % (tool_name, truth_name), 0)
    self.skip_document.add_page_break ()

  #
  # Get the correct tool object from the provided result set
  #
  def get_tool (self, rs):
    for tool in Utilities.get_tools ():
      if rs.GetSource () == tool.name ():
        logging.debug ('Using tool [%s]' % tool)
        return tool

    logging.error ('ERROR: Unable to find tool for source [%s]' % rs.GetSource ())
    sys.exit (1)
