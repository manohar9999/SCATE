from ...DataAbstractions import *

from collections import defaultdict
import logging

#
# Result class for storing tp, fp, and fn
#
class Result:
  def __init__ (self):
    self.tp = 0
    self.fn = 0

  def percent_found (self):
    try:
      return (self.tp * 1.0) / (self.tp + self.fn) * 100
    except Exception as e:
      return 0

#
# Detailed Page generator
#
class DetailedPage:
  #
  # Name of the page
  #
  @staticmethod
  def name ():
    return 'Detail'

  #
  # Constructor
  #
  def __init__ (self):
    self._results = None
    self._tex_name = None
    self._tool_name = None
    self._weaknesses = None

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
    self._results = defaultdict (Result)

    self._tex_name = 'detailed.%s.%s' % (organizer.build_rs.GetSource (),
                     str (organizer.grainularity).split('.')[-1])

    if not wrong_checker_is_fp:
      self._tex_name += '.skip'

    self._tool_name = organizer.build_rs.GetSource ()

  #
  # Visit datapoint
  #
  def visit (self, datapoint):
    self._results[datapoint.weakness].tp += datapoint.tp
    self._results[datapoint.weakness].fn += datapoint.fn

  #
  # fini
  #
  def fini (self):
    fp = open ('%s.tex' % self._tex_name, 'w')
    self.write_header (fp)

    # Write results per CWE
    for weakness in sorted (self._results):
      self.write_result (fp, weakness, self._results[weakness])

    self.write_footer (fp)
    fp.close ()

  #
  # Write latex header
  #
  def write_header (self, fp):
    fp.write ("\\centering{\\section{Detailed Analysis Table}}\n\n")
    fp.write ("\\begin{longtable}{| p{.20\\textwidth} | p{.20\\textwidth} | p{.20\\textwidth} | p{.20\\textwidth} | p{.20\\textwidth} |}\n")
    fp.write ("\\hline\n")
    fp.write ("Test Case & Tool & Undetected Flaws & Detected Flaws & \\% Found \\\\ [0.5ex]\n")
    fp.write ("\\hline\n")

  #
  # Write latex footer
  #
  def write_footer (self, fp):
    fp.write ("\\caption{auto-generated analysis table.}")
    fp.write ("\\label{tab:myfirstlongtable}")
    fp.write ("\\end{longtable}")
    fp.write ("\n\\newpage")

  #
  # Write single Result
  #
  def write_result (self, fp, weakness, result):
    fp.write ("\\multirow{1}{*}{\\hyperlink{%s}{\\underline{%s}}}\n"
      % (weakness, weakness))
    fp.write ("& %s & %d & %d & %.2f \\\\ \\cline{2-5}\n"
      % (self._tool_name, result.fn, result.tp, result.percent_found ()))
    fp.write ("\\hline\n")
