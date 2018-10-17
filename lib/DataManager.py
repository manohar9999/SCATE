#!/bin/env python

################################################################################
#
# file : DataManager.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################


#
# Base class - DataManager
#
class DataManager:
  #
  # Type of DataManager
  #
  def type (self):
    yield

  #
  # Initialise DataManager based on arguments provided
  # for read target will be a filename
  # For write target will be a filepath
  #
  def init (self,target):
    pass

  #
  # Reads the Data
  #
  def add_results (self,ResultSet):
    pass

  #
  # Writes the Data
  #
  def write (self,ResultSet):
    pass

  #
  # Reads a Datapoint file
  #
  def read_datapointset (self):
    pass

  #
  # Writes a Datapoint file
  #
  def write_datapointset (self, datapointset):
    pass
