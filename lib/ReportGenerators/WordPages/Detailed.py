from ...DataAbstractions import *
from ..WordGenerator import Organizer

from collections import defaultdict
import logging

#
# Result class for storing tp, fp, and fn
#
class Result:
  def __init__ (self):
    self.tp = 0
    self.fn = 0
    self.fp = 0

  def percent_found (self):
    try:
      return (self.tp * 1.0) / (self.tp + self.fn) * 100
    except Exception as e:
      return 0

#
# Detailed Page generator
#
class DetailedPage:
  #
  # Name of the page
  #
  @staticmethod
  def name ():
    return 'Detail'

  #
  # Constructor
  #
  def __init__ (self):
    self._file_results = {}
    self._function_results = {}
    self._line_results = {}
    self._results = defaultdict (Result)
    self._weaknesses = set ()
    self._granularity = None

  #
  # Initialize the page
  #
  def init (self, organizer, wrong_checker_is_fp):
    self.assign_result ()
    self._granularity = organizer.granularity
    self._results = defaultdict (Result)


  def assign_result (self):
    if self._granularity == Organizer.Granularity.FILENAME:
      self._file_results = self._results
    elif self._granularity == Organizer.Granularity.FUNCTION:
      self._function_results = self._results
    elif self._granularity == Organizer.Granularity.LINE:
      self._line_results = self._results

  #
  # Visit datapoint
  #
  def visit (self, datapoint):
    self._results[datapoint.weakness].tp += datapoint.tp
    self._results[datapoint.weakness].fn += datapoint.fn
    self._results[datapoint.weakness].fp += datapoint.fp

  #
  # fini
  #
  def fini (self, document):
    self.assign_result ()

    document.add_heading ('Detailed Analysis Table')

    self.write_result (document, 'Filename', self._file_results)
    self.write_result (document, 'Function', self._function_results)
    self.write_result (document, 'Line', self._line_results)

    document.add_page_break ()

  #
  # Write single Result
  #
  def write_result (self, document, granularity, results):
    document.add_heading ('%s Granularity' % granularity, level=4)
    table = document.add_table (rows=1, cols=6)
    header = table.rows[0].cells
    header[0].text = 'Test Case'
    header[1].text = 'Expected Flaws'
    header[2].text = 'TP'
    header[3].text = 'FP'
    header[4].text = 'FN'
    header[5].text = '% Found'

    for weakness in sorted (results):
      cells = table.add_row ().cells
      cells[0].text = '%s' % weakness
      cells[1].text = '%d' % (results[weakness].fn + results[weakness].tp)
      cells[2].text = '%d' % results[weakness].tp
      cells[3].text = '%d' % results[weakness].fp
      cells[4].text = '%d' % results[weakness].fn
      cells[5].text = '%.2f' % results[weakness].percent_found ()
