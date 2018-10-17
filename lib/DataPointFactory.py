#!/bin/env python

################################################################################
#
# file : DataPointFactory.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################

#
# Base class - DataPointFactory
#
class DataPointFactory:
  #
  # Constructor
  #
  def __init__ (self, result_set):
    pass

  # {@ Export Hooks

  #
  # Genearates DataPoints
  #
  def generate (self, granularity, wrong_checker_is_fp, minimum):
    pass

  # @}
