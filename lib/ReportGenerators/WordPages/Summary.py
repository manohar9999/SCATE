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
    self.fp = 0
    self.fn = 0
    self.expected = 0

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
# Base class - ReportGenerator
#
class SummaryPage:
  #
  # Name of the page
  #
  @staticmethod
  def name ():
    return 'Summary'

  #
  # Constructor
  #
  def __init__ (self):
    self._file_result = Result ()
    self._function_result = Result ()
    self._line_result = Result ()
    self._weaknesses = set () 
    self._result = Result ()
    self._granularity = None

  #
  # Initialize the page
  #
  def init (self, organizer, wrong_checker_is_fp):
    self.assign_result ()
    self._granularity = organizer.granularity
    self._result = Result ()

  def assign_result (self):
    if self._granularity == Organizer.Granularity.FILENAME:
      self._file_result = self._result
    elif self._granularity == Organizer.Granularity.FUNCTION:
      self._function_result = self._result
    elif self._granularity == Organizer.Granularity.LINE:
      self._line_result = self._result

  #
  # Visit datapoint
  #
  def visit (self, datapoint):
    self._result.expected += datapoint.tp + datapoint.fn
    self._result.tp += datapoint.tp
    self._result.fp += datapoint.fp
    self._result.fn += datapoint.fn

    self._weaknesses.add (datapoint.weakness)

  #
  # fini
  #
  def fini (self, document):
    self.assign_result ()

    document.add_heading ('Summary')
    table = document.add_table (rows=4, cols=8)

    header = table.rows[0].cells
    header[0].text = 'Granularity'
    header[1].text = 'Weaknesses'
    header[2].text = 'Expected'
    header[3].text = 'TP'
    header[4].text = 'FP'
    header[5].text = 'FN'
    header[6].text = 'Precision'
    header[7].text = 'Recall'

    self.write_results ('Filename', self._file_result, table.rows[1].cells)
    self.write_results ('Function', self._function_result, table.rows[2].cells)
    self.write_results ('Line', self._line_result, table.rows[3].cells)
    document.add_page_break ()

  #
  # write results to cells
  #
  def write_results (self, label, result, cells):
    cells[0].text = label
    cells[1].text = '%d' % len (self._weaknesses)
    cells[2].text = '%d' % result.expected
    cells[3].text = '%d' % result.tp
    cells[4].text = '%d' % result.fp
    cells[5].text = '%d' % result.fn
    cells[6].text = '%.2f' % result.precision ()
    cells[7].text = '%.2f' % result.recall ()
