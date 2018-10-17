from ...DataAbstractions import *
from ... import Utilities
from ..LatexGenerator import Organizer

import logging

#
# Base class - ReportGenerator
#
class MethodologyPage:
  #
  # Name of the page
  #
  @staticmethod
  def name ():
    return 'Methodology'

  #
  # Constructor
  #
  def __init__ (self):
    self._tex_name = None
    self._tool = None
    self._import_suite = None
    self._tool_args = None
    self._import_suite_args = None
    self._analyze_string = None

  #
  # Get the name of the tex file
  #
  def tex_name (self):
    return self._tex_name

  #
  # Initialize the page
  #
  def init (self, organizer, wrong_checker_is_fp):
    # Init can be called multiple times (i.e. flyweight)
    self._tex_name = 'methodology.%s.%s' % (organizer.build_rs.GetSource (),
                     str (organizer.grainularity).split('.')[-1])

    if not wrong_checker_is_fp:
      self._tex_name += '.skip'

    for tool in Utilities.get_tools ():
      if tool.name () == organizer.build_rs.GetSource ():
        self._tool = tool ()

    for import_suite in Utilities.get_importsuites ():
      if import_suite.name () == organizer.truth_rs.GetSource ():
        self._import_suite = import_suite ()

    self._tool_args = organizer.build_rs.GetArgs ()
    self._import_suite_args = organizer.truth_rs.GetArgs ()

    if organizer.grainularity == Organizer.Grainularity.FILENAME:
      self._analyze_string = self.filename_criteria (wrong_checker_is_fp)
    elif organizer.grainularity == Organizer.Grainularity.FUNCTION:
      self._analyze_string = self.function_criteria (wrong_checker_is_fp)
    elif organizer.grainularity == Organizer.Grainularity.LINE:
      self._analyze_string = self.line_criteria (wrong_checker_is_fp)

  #
  # Latex output for filename criteria
  #
  def filename_criteria (self, wrong_checker_is_fp):
    results = '''
This report used the Filename methodolgy for identifying true positives (TP),
false positives (FP) and false negatives (FN). The following criteria is
applied:

\\begin{itemize}
  \\item TP: The SCA tool found a Bug with the correct checker for the weakness in a file.
  \\item FN: The SCA tool found less TPs than expected in a file, the difference between the expected number of TPs and those found are FNs.
  \\item FP: The SCA tool found more TPs than expected in a file, the difference between the number of TPs found and number expected are FPs.
'''

    if wrong_checker_is_fp == True:
      results += ''' Additionally, any Bugs found with the wrong checker for the weakness are
considered FPs.
'''

    results += '''
\\end {itemize}

To apply this critera, the following steps are taken:
\\begin{enumerate}
  \\item All Flaws from the import file are grouped by filename.
  \\item All Bugs identified by the tool from the build file are grouped by filename.
  \\item Any Bugs reported by the tool in filenames where Flaws were not expected are skipped.
  \\item Any Incidental Flaws which were correctly identified by the tool are skipped.
  \\item Fixes are removed from the expected number of TPs.
  \\item The above criteria for TP, FN, and FP is applied.
\\end{enumerate}'''

    return results

  #
  # Latex output for function criteria
  #
  def function_criteria (self, wrong_checker_is_fp):
    results = '''
This report used the Function methodolgy for identifying true positives (TP),
false positives (FP) and false negatives (FN). The following criteria is
applied:

\\begin{itemize}
  \\item TP: The SCA tool found a Bug with the correct checker for the weakness in a 'bad' function.
  \\item FN: The SCA tool found less TPs than expected in a function, the difference between the expected number of TPs and those found are FNs.
  \\item FP: The SCA tool found more TPs than expected in a function, the difference between the number of TPs found and number expected are FPs. Also,
    any Bugs with the correct checker in a function with 'good' in its name is a FP.
'''

    if wrong_checker_is_fp == True:
      results += ''' Additionally, any Bugs found with the wrong checker for the weakness are
considered FPs.
'''

    results += '''
\\end {itemize}

To apply this critera, the following steps are taken:
\\begin{enumerate}
  \\item All Flaws from the import file are grouped by filename and function.
  \\item All Bugs identified by the tool from the build file are grouped by filename and function.
  \\item Any Bugs reported by the tool in files or functions where Flaws were not expected are skipped.
  \\item Any Incidental Flaws which were correctly identified by the tool are skipped.
  \\item Fixes are removed from the expected number of TPs.
  \\item The above criteria for TP, FN, and FP is applied.
\\end{enumerate}'''

    return results

  #
  # Latex output for line criteria
  #
  def line_criteria (self, wrong_checker_is_fp):
    results = '''
This report used the Line methodolgy for identifying true positives (TP),
false positives (FP) and false negatives (FN). The following criteria is
applied:

\\begin{itemize}
  \\item TP: The SCA tool found a Bug with the correct checker for the weakness in a 'bad' function on the correct line.
  \\item FN: The SCA tool found less TPs than expected on a line, the difference between the expected number of TPs and those found are FNs.
  \\item FP: The SCA tool found more TPs than expected on a line, the difference between the number of TPs found and number expected are FPs. Also,
    any Bugs with the correct checker in a function with 'good' in its name is a FP.
'''

    if wrong_checker_is_fp == True:
      results += ''' Additionally, any Bugs found with the wrong checker for the weakness are
considered FPs.
'''

    results += '''
\\end {itemize}

To apply this critera, the following steps are taken:
\\begin{enumerate}
  \\item All Flaws from the import file are grouped by filename, function, and line.
  \\item All Bugs identified by the tool from the build file are grouped by filename, function, and line.
  \\item Any Bugs reported by the tool on lines where Flaws were not expected are skipped.
  \\item Any Incidental Flaws which were correctly identified by the tool are skipped.
  \\item Fixes are removed from the expected number of TPs.
  \\item The above criteria for TP, FN, and FP is applied.
\\end{enumerate}'''

    return results

  #
  # Visit datapoint
  #
  def visit (self, datapoint):
    pass

  #
  # fini
  #
  def fini (self):
    fp = open ('%s.tex' % self._tex_name, 'w')
    fp.write ('\\begin{center}\\section{Methodology}\n')
    fp.write ('\\subsection{Import TestSuite}\\end{center}\n')

    fp.write ('%s' % self._import_suite.methodology (self._import_suite_args))

    fp.write ('\\begin{center}\\subsection{Build with SCA Tool}\\end{center}')
    fp.write ('%s' % self._tool.methodology (self._tool_args))

    fp.write ('\\begin{center}\\subsection{Analyze Results}\\end{center}')
    fp.write ('%s' % self._analyze_string)
    fp.write ('\\newpage\n')
    fp.close ()
