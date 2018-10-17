from ..ReportGenerator import ReportGenerator
from ..DataAbstractions import *
from .. import Utilities

import logging
import csv
import sys
from enum import Enum
from collections import defaultdict
import re

#
# Factory Method for Test Suites
#
def __create__ ():
  return PivotTableGenerator ()

#
# Pivot Table Generator
#
class PivotTableGenerator (ReportGenerator):
  #
  # Initialize the parser
  #
  @staticmethod
  def init_parser (parser):
    pt_parser = parser.add_parser ('pivot_table', help='Convert evidence into a pivot table format')
    pt_parser.set_defaults (generator=PivotTableGenerator)

  #
  # Initalize the generator
  #
  def parse_args (self, args):
    # Call the base class (Command) init
    super (PivotTableGenerator, self).parse_args (args)

  #
  # Generate the report
  #
  def generate (self, datapointset):
    # Construct the appropriate Tool object which was used for the build
    self.datapointset = datapointset
    self.tool_name = '_'.join (datapointset.builds.keys ())
    self.truth_name = '_'.join (datapointset.imports.keys ())

    logging.info ('Generating pivot table reports')
    self.write_probabilities ()

  #
  # Write the probability files
  #
  def write_probabilities (self):
    # We create two permutations for each granularity:
    # One where Bugs with wrong checkers count as false postives ([tool].[granularity].csv)
    # One where Bugs with wrong checkers don't count as false positives ([tool].[granularity].skip.csv)
    for criteria in self.datapointset.iterate_Criterias ():
      filename = self.get_filename (criteria)
      writer = csv.writer (open (filename, 'w'))
      writer.writerow (['weakness', 'directory', 'filename', 'function', 'line', 'tool', 'tp', 'fp', 'fn'])

      for datapoint in criteria.iterate_DataPoints ():
        self.visit_datapoint (datapoint, writer)

  #
  # Get the filename from the provided criteria 
  #
  def get_filename (self, criteria):
    filename = '%s.%s' % (self.tool_name, criteria.granularity.name)
    
    if not criteria.wrong_checker_is_fp:
      filename += '.skip'

    if criteria.minimum:
      filename += '.min'
    else:
      filename += '.max'

    filename += '.csv'
    return filename

  #
  # Visit a datapoint and write its state to the CSV
  #
  def visit_datapoint (self, datapoint, writer):
    row = ['%s' % datapoint.weakness,
           '%s' % datapoint.directory,
           '%s' % datapoint.filename,
           '%s' % datapoint.function,
           '%s' % datapoint.line]

    truth_row = []
    truth_row.extend (row)
    truth_row.append (self.truth_name)
    truth_row.extend ([datapoint.tp + datapoint.fn, 0,0])
    writer.writerow (truth_row)

    tool_row = []
    tool_row.extend (row)
    tool_row.append (self.tool_name)
    tool_row.extend ([datapoint.tp, datapoint.fp, datapoint.fn])
    writer.writerow (tool_row)
