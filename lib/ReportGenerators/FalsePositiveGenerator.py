from ..ReportGenerator import ReportGenerator
from ..DataAbstractions import *
from .. import Utilities
from ..DataManagers.XMLManager import XMLManager

import logging

#
# Factory Method for Test Suites
#
def __create__ ():
  return FalsePositiveGenerator ()

#
# Pivot Table Generator
#
class FalsePositiveGenerator (ReportGenerator):
  #
  # Initialize the parser
  #
  @staticmethod
  def init_parser (parser):
    fp_parser = parser.add_parser ('fp', help='Filter export to only include false positives')
    fp_parser.add_argument ('--outfile', type=str, required=True, help='Output file')
    fp_parser.set_defaults (generator=FalsePositiveGenerator)

  #
  # Initalize the generator
  #
  def parse_args (self, args):
    # Call the base class (Command) init
    super (FalsePositiveGenerator, self).parse_args (args)
    self.__outfile__ = args.outfile

  #
  # Generate the report
  #
  def generate (self, datapointset):
    logging.info ('Generating false positive report')

    for criteria in datapointset.iterate_Criterias ():
      self.filter_datapoints (criteria)

    # Write the filtered DataPointSet
    xmlm = XMLManager (self.__outfile__)
    xmlm.write_datapointset (datapointset)

  #
  # Filter the input criteria to only include datapoints that have false
  # positives
  #
  def filter_datapoints (self, criteria):
    # Iterate in reverse so we don't skip values (values shift forward
    # upon deletion).  Subtract by 1 because lists are 0-indexed
    for i in range (len (criteria.datapoints) - 1, -1, -1):
      if criteria.datapoints[i].fp == 0:
        del (criteria.datapoints[i])
