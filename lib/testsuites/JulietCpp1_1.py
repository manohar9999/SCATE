#!/bin/env python

################################################################################
#
# file : JulietCpp1_1.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################

from .JulietCpp import JulietCpp

#
# Factory Method for Test Suites
#
def __create__ ():
  return JulietCpp1_1 ()

class JulietCpp1_1 (JulietCpp):
  def __init__ (self):
    super (JulietCpp1_1, self).__init__ ('1.1')
