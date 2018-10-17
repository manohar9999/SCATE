#!/bin/env python

################################################################################
#
# file : XMLManager.py
#
# author: Lakshmi Manohar Rao Velicheti - lveliche@iupui.edu
##
################################################################################

import os
import logging
import lxml

from ..DataManager import DataManager
from ..DataAbstractions import ResultSet, Weakness, Suite, File, Function, Line, Flaw, FlawType, Bug, DataPointSet, \
    DataPointCriteria, DataPoint

from lxml import etree
from lxml import objectify
from lxml import sax
from xml.sax.handler import ContentHandler


#
# Factory Method for DataManager
#
def __create__ ():
    return XMLManager ()


#
# Basic SAX Writer class to write to a file
# using SAX instead of DOM to reduce memory
# usage
#
class SAXWriter (ContentHandler):
    def __init__ (self, outfile, spaces_per_level):
        self.spaces_per_level = spaces_per_level
        self.level = 0
        self.ostream = open (outfile, 'wb')
        self.previous_level = 0

    def startDocument (self):
        pass

    def startElementNS (self, name, qname, attributes):
        uri, localname = name

        if self.level > self.previous_level:
            # End parent element tag
            self.write ('>\n', True)

        if attributes.getLength ():
            xml = '<%s %s' % (localname, ' '.join (['%s="%s"' % (key[1], value) for key, value in attributes.items ()]))
        else:
            xml = '<%s' % localname

        self.write (xml)

        self.previous_level = self.level
        self.level += 1

    def endElementNS (self, name, qname):
        self.level -= 1
        uri, localname = name

        if self.level == self.previous_level:
            self.write ('/>\n', True)
        else:
            self.write ('</%s>\n' % localname)

    def write (self, text, skip_align = False):
        fixed_text = self.convert (text)

        if skip_align:
            self.ostream.write (bytes ('%s' % fixed_text, 'UTF-8'))
        else:
            self.ostream.write (bytes ('%s%s' % (' ' * self.spaces_per_level * self.level, fixed_text), 'UTF-8'))

    def convert (self, text):
        return text.replace ('&', '&amp;')


#
# @class XMLManager
#
# Concrete class XMLManager derived from DataManager
#
class XMLManager (DataManager):
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
        return 'XML'

    #
    # Reads the Data returning a Result Set
    #
    def add_results (self, result_set, is_build):
        try:
            tree = objectify.parse (self.__file_target__)
            root = tree.getroot ()

            for result in root.iter ('result'):
                if result.get ('name'):
                    result_set.name = result.get ('name')

                if result.get ('source'):
                    result_set.source = result.get ('source')

                if result.get ('args'):
                    result_set.args = result.get ('args')

                if is_build:
                    result_set.builds[result.get ('source')] = result.get ('args')
                else:
                    result_set.imports[result.get ('source')] = result.get ('args')

                for weakness in result.iter ('weakness'):
                    if not weakness.get ('id') in result_set.weaknesses:
                        weakness_obj = Weakness.from_xml (weakness, result_set)
                        result_set[weakness_obj.name] = weakness_obj

                    weakness_obj = result_set[weakness.get ('id')]

                    for suite in weakness.iter ('suite'):
                        if not suite.get ('dir') in weakness_obj.suites:
                            suite_obj = Suite.from_xml (suite, weakness_obj)
                            weakness_obj[suite_obj.directory] = suite_obj
                        suite_obj = weakness_obj[suite.get ('dir')]

                        for flaw in suite.iter ('flaw'):
                            filename = flaw.get ('file')
                            function = flaw.get ('function')
                            line = int (flaw.get ('line'))

                            if not filename in suite_obj.files:
                                file = File.from_xml (flaw, suite_obj)
                                suite_obj[filename] = file

                            if not function in suite_obj[filename].functions:
                                function_obj = Function.from_xml (flaw, suite_obj[filename])
                                suite_obj[filename][function] = function_obj

                            if not line in suite_obj[filename][function].lines:
                                line_obj = Line.from_xml (flaw, suite_obj[filename][function])
                                suite_obj[filename][function][line] = line_obj

                            flaw_obj = Flaw.from_xml (flaw, suite_obj[filename][function][line], result_set.source)

                            if not flaw_obj in suite_obj[filename][function][line].get_Flaws ():
                                suite_obj[filename][function][line].add_Flaw (flaw_obj)

                        for bug in suite.iter ('bug'):
                            filename = bug.get ('filename')
                            function = bug.get ('function')
                            line = int (bug.get ('line'))

                            if not filename in suite_obj.files:
                                file = File.from_xml (bug, filename)
                                file.suite = suite_obj
                                suite_obj[filename] = file

                            if not function in suite_obj[filename].functions:
                                function_obj = Function.from_xml (bug, function)
                                function_obj.file = suite_obj[filename]
                                suite_obj[filename][function] = function_obj

                            if not line in suite_obj[filename][function].lines:
                                line_obj = Line.from_xml (bug, line)
                                line_obj.function = suite_obj[filename][function]
                                suite_obj[filename][function][line] = line_obj

                            bug_obj = Bug.from_xml (bug, result_set.source)
                            bug_obj.line = suite_obj[filename][function][line]
                            suite_obj[filename][function][line].add_Bug (bug_obj)

        except lxml.etree.XMLSyntaxError:
            logging.error ('Syntax error reading XML [%s]' % self.__file_target__)
            return

    #
    # Writes the Data
    # @param in : result_set
    #
    # writes result to file which is initialised in constructor
    # if no file name is specified it the filename would be same as
    # source
    #
    def write (self, result_set):
        logging.info ('writing %s' % self.type ())

        if self.__file_target__ is None:
            writer = SAXWriter (result_set.source, 2)
        else:
            writer = SAXWriter (self.__file_target__, 2)

        logging.info ('write from source: %s' % result_set.source)
        resultset_w = etree.Element ('result')
        resultset_w.set ("source", result_set.source)
        resultset_w.set ('args', result_set.args)

        from html import escape

        for weakness in result_set.iterate_Weaknesses ():
            weaknesselement = etree.SubElement (resultset_w, "weakness")
            weaknesselement.set ("id", weakness.name)

            for suite in weakness.iterate_Suites ():
                suiteelement = etree.SubElement (weaknesselement, "suite")

                suiteelement.set ("dir", suite.directory)
                suiteelement.set ("tool", suite.compiler)
                suiteelement.set ("args", suite.args)

                for file in suite.iterate_Files ():
                    for function in file.iterate_Functions ():
                        for line in function.iterate_Lines ():

                            for flaw in line.iterate_Flaws ():

                                flawelement = etree.SubElement (suiteelement, "flaw")
                                attrib = flawelement.attrib

                                attrib['file'] = file.filename
                                attrib['function'] = function.function
                                attrib['line'] = str (line.line)
                                attrib['severity'] = str (flaw.severity.name)
                                attrib['description'] = escape (flaw.description)

                            for bug in line.iterate_Bugs ():
                                bugelement = etree.SubElement (suiteelement, "bug")
                                attrib = bugelement.attrib
                                attrib['filename'] = file.filename
                                attrib['function'] = function.function
                                attrib['line'] = str (line.line)
                                attrib['type'] = bug.type
                                attrib['message'] = escape (bug.message)

        sax.saxify (resultset_w, writer)

        if self.__file_target__ is None:
            logging.info ("Write successful on file: %s" % (result_set.source))
        else:
            logging.info ("Write successful on file: %s" % (self.__file_target__))

    #
    # Writes a Datapoint File
    #
    def write_datapointset (self, datapointset):
        logging.info ('writing %s' % self.type ())
        writer = SAXWriter (self.__file_target__, 2)

        datapointset_x = etree.Element ('datapointset')

        for (source, args) in datapointset.imports.items ():
            xml = etree.SubElement (datapointset_x, 'import')
            xml.set ('source', source)
            xml.set ('args', args)

        for (source, args) in datapointset.builds.items ():
            xml = etree.SubElement (datapointset_x, 'build')
            xml.set ('source', source)
            xml.set ('args', args)

        for criteria in datapointset.iterate_Criterias ():
            criteria_x = etree.SubElement (datapointset_x, 'criteria')

            criteria_x.set ('granularity', criteria.granularity.name)
            criteria_x.set ('wrong_checker_is_fp', str (criteria.wrong_checker_is_fp))
            criteria_x.set ('minimum', str (criteria.minimum))

            for datapoint in criteria.iterate_DataPoints ():
                xml = etree.SubElement (criteria_x, 'datapoint')
                xml.set ('tp', str (datapoint.tp))
                xml.set ('fp', str (datapoint.fp))
                xml.set ('fn', str (datapoint.fn))
                xml.set ('weakness', datapoint.weakness)
                xml.set ('directory', datapoint.directory)
                xml.set ('filename', datapoint.filename)
                xml.set ('function', datapoint.function)
                xml.set ('line', str (datapoint.line))
                xml.set ('permutation', datapoint.permutation)

        sax.saxify (datapointset_x, writer)

    #
    # Reads a DataPoint file
    #
    def read_datapointset (self, datapointset):
        root = objectify.parse (self.__file_target__).getroot ()

        for datapointset_x in root.iter ('datapointset'):
            for xml in datapointset_x.iter ('import'):
                datapointset.imports[xml.get ('source')] = xml.get ('args')

            for xml in datapointset_x.iter ('build'):
                datapointset.builds[xml.get ('source')] = xml.get ('args')

            for criteria_x in datapointset_x.iter ('criteria'):
                criteria = DataPointCriteria.from_xml (criteria_x)
                criteria.datapointset = datapointset
                datapointset[(criteria.granularity, criteria.wrong_checker_is_fp, criteria.minimum)] = criteria

                for xml in criteria_x.iter ('datapoint'):
                    dp = DataPoint.from_xml (xml)
                    dp.criteria = criteria
                    criteria.datapoints.append (dp)
