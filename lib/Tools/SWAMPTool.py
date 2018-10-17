################################################################################
#
# file : SwampTools.py
#
# author: Enas Alikhashashneh <ealikhas@umail.iu.edu>
#
################################################################################

from ..Tool import Tool
from ..DataAbstractions import ResultSet, Weakness, Suite, File, Function, Line, Flaw, Bug
from ..DataManagers.XMLManager import XMLManager
from ..DataManagers.CSVManager import CSVManager
from .. import Utilities

import os
import subprocess
import logging
import sys
import xml
import io

class SWAMPTool(Tool):
  def __init__ (self):
    super (SWAMPTool, self).__init__ ('swamp', {})

    self.__root_dir__ = None
    self.__subtool__ = None

  # intialize variables
  def init (self, Dir, SubTool):
      self.__root_dir__ = Dir
      self.__subtool__ = SubTool

  # Handle generating the build document for a suite
  def handle_docgen(self, Suite):
     FilesList = [f for f in os.listdir (self.__root_dir__)
                  if os.isfile (os.path.join(self.__root_dir__,f))]

     for FN in FilesList:
       fn = self.__root_dir__ + "\\" + FN

       # Read Xml file and extract data for Suite
       with io.open(fn,'r') as file:
           XmlFile = xm(file)
           root = XmlFile.getroot() # start analysis
           Source = root.get('tool_name')
           for child in root.findall('BugInstance'):
               # find file
               temp = child.findtext('BugLocations/Location/SourceFile')
               suit,FileName = os.path.split(temp)

               #create new file
               if not FileName in Suite.files:
                   Suite[FileName] = File(FileName)

               # create new function
               Meth = child.findtext('Methods')
               if not Meth in Suite[FileName].functions:
                   Suite[FileName][Meth] = Function(Meth)

               # create new line
               LineNum = int(child.findtext('BugLocations/Location/StartLine'))
               if not LineNum in Suite[FileName][Meth].lines:
                  Suite[FileName][Meth][LineNum] = Line(LineNum)

               # create new bug
               type = child.findtext('BugCode')
               BU = Bug(type,Source)
               Suite[FileName][Meth][LineNum].add_Bug(BU)
