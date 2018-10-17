from DataAbstraction import Bug,Suite, Weakness, File,Function,Line, ResultSet
from DataManager import *
from XMLManager import *
from os import *
from SWAMPTool import *
from Tool import Tool
from os.path import isfile, join
import sys
import logging
from CppCheck import *
import io
from xml.etree.ElementTree import parse as xm
import xml.etree.ElementTree as ET
from xml import parsers
from xml.sax.handler import ContentHandler

class SwampManager(DataManager):

    def __init__(self):
        self.FileTarget = None
        self.RootDir = None
    
    def init(self, FileTarget=None, RootDir=None):
        self.FileTarget = FileTarget
        self.RootDir = RootDir

    def read(self, ResultSet):
       
       FilesList = [f for f in listdir(self.RootDir) if isfile(join(self.RootDir,f))]
       for FN in FilesList:
         fn = self.RootDir + "\\" + FN
         self.FileTarget = fn
         
         # Read Xml file and extract data for results, weakness, Suits, and
         # Bugs
         with io.open(self.FileTarget,'r') as file:
             XmlFile = xm(file)
             root = XmlFile.getroot() # start analysis
             Source = root.get('tool_name') # Source of result
             ResultSet.source = Source
             # Create new weakness instance and get the weakness name
             weakness_name, SN = os.path.split(self.FileTarget)[1].split('_')
             
             if not weakness_name in ResultSet.weaknesses:
                 weakness = Weakness(weakness_name)
                 ResultSet[weakness.name] = weakness
             WeaknessObj = ResultSet[weakness_name] 

             for child in root.findall('BugInstance'):
                 # find suite
                 temp = child.findtext('BugLocations/Location/SourceFile')
                 suit,FileName = os.path.split(temp)
                 dir = os.path.join(self.RootDir,suit) # extract directory
                 FN, args = os.path.splitext(FileName) # extract suites arg

                 #create new Suite
                 if not dir in WeaknessObj.suites:
                     ST = Suite(dir,' ', ' ')
                     WeaknessObj[ST.directory] = ST
                 SuiteObj = WeaknessObj[dir] 
                                                 
                 #create new file
                 if not FileName in SuiteObj.files:
                     FL = File(FileName)
                     SuiteObj[FL.filename] = FL
                 FileObj = SuiteObj[FileName]

                 # create new function
                 Meth = child.findtext('Methods')
                 if not Meth in FileObj.functions:
                     FT = Function(Meth)
                     FileObj[FT.function] = FT
                 FunctionObj = FileObj[Meth]
                 
                 # create new line
                 LineNum = int(child.findtext('BugLocations/Location/StartLine'))
                 LN = Line(LineNum)
                 if not LineNum in FunctionObj.lines:
                    LN = Line(LineNum)
                    FunctionObj[LN.line] = LN
                 LineObj = FunctionObj[LineNum]
                 
                 # create new bug
                 type = child.findtext('BugCode')
                 BU = Bug(type,Source)
                 LineObj.add_Bug(BU)
                                                                          
    def type(self):
          return 'XML'

   