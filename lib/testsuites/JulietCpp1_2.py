#!/bin/env python

################################################################################
#
# file : JulietCpp1_2.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
#
################################################################################

from .JulietCpp import JulietCpp

import logging

#
# Factory Method for Test Suites
#
def __create__ ():
  return JulietCpp1_2 ()

class JulietCpp1_2 (JulietCpp):
  def __init__ (self):
    super (JulietCpp1_2, self).__init__ ('1.2')

