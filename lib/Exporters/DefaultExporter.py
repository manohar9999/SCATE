#!/bin/env python

################################################################################
#
# file : SCATE_Exporter.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

from ..Exporter import Exporter
from ..DataAbstractions import *
from ..DataPointFactories.NIST_Cpp_DPFactory import NIST_Cpp_DPFactory
from ..DataManagers.XMLManager import XMLManager
from .. import Utilities

def __create__ ():
  return DefaultExporter ()

#
# @class SCATE_Exporter
#
# Exporter for use with SCATE python report generators
#
class DefaultExporter (Exporter):
  def __init__ (self):
    super (DefaultExporter, self).__init__ ('scate')
    self.needs_min_max = None

  def init_parser (self, parser):
    subparser = parser.add_parser ('scate', help='default exporter used with report generators')
    subparser.set_defaults (exporter=self)

  def export (self, merged_rs, datapointset, filename):

    # Find out if we need to apply the minimum/maximum criteria
    self.needs_min_max = Utilities.needs_min_max (merged_rs)

    # Use the NIST_Cpp_DPFactory, since that's the only factory we have right now
    factory = NIST_Cpp_DPFactory (merged_rs)

    # Generate datapoints for each permutation available (granularity and wrong checker)
    for (granularity, wrong_checker_is_fp, minimum) in self.permutations ():
      logging.debug ('Processing criteria (%s:%s:%s)' % (granularity, wrong_checker_is_fp, minimum))
      criteria = DataPointCriteria (granularity, wrong_checker_is_fp, minimum)

      for datapoint in factory.generate (granularity, wrong_checker_is_fp, minimum):
        if datapoint.filename in merged_rs.weaknesses[datapoint.weakness].suites[datapoint.directory].files:
          criteria.datapoints.append(datapoint)
        else:
          logging.warning("Disregarding file '%s' in suite '%s': File not defined in KB!" % (datapoint.filename, datapoint.directory))

      datapointset[(granularity, wrong_checker_is_fp, minimum)] = criteria

    # Write the results
    xmlm = XMLManager (filename)
    xmlm.write_datapointset (datapointset)

  def permutations (self):
    # Yield all the permutations we handle
    for granularity in [Granularity.Filename, Granularity.Function, Granularity.Line]:
      for wrong_checker_is_fp in [True, False]:
        if self.needs_min_max:
          for min_max in [True, False]:
            yield (granularity, wrong_checker_is_fp, min_max)
        else:
          yield (granularity, wrong_checker_is_fp, True)
