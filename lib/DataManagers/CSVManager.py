#!/bin/env python

################################################################################
#
# file : CSVManager.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

import os
from ..DataManager import DataManager
from ..DataAbstractions import ResultSet, Weakness, Suite, Flaw
import csv
import time

#
# Factory Method for DataManager
#
def __create__ ():
  return CSVManager()

#
# @class CSVManager
#
# Concrete class CSVManager derived from DataManager
#
class CSVManager (DataManager):
  #
  # Initialise DataManager based on arguments provided
  #
  #
  def __init__ (self, target = None):
    self.__file_target__ = target


  #
  # Returns type of Data Manager
  #
  def type (self):
    return 'CSV'

  #
  # Reads the Data
  # @ param in : Resultset
  #
  def add_results (self ,Resultset):
    return

  #
  # Writes the Data
  # @param in : List waiting to be written,
  # and source of the list i.e., tool name
  #
  def write (self, list_, source_name):
    print ("Writing ..%s" % (self.type ()))

    # Appending time stamp to output file
    timestr = time.strftime ("%Y%m%d-%H%M%S")
    filename = '%s_%s_.csv' % (source_name, timestr)
    filep = open (filename,'w')

    writer = csv.writer (filep, lineterminator='\n')
    for row_ in list_:
      writer.writerow(row_)

    print ("Write successful")
