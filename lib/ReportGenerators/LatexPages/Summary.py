from ...DataAbstractions import *

from collections import defaultdict
import logging

#
# Result class for storing tp, fp, and fn
#
class Result:
  def __init__ (self):
    self.tp = 0
    self.fp = 0
    self.fn = 0
    self.expected = 0

  def precision (self):
    try:
      return self.tp / (self.tp + self.fp * 1.0)
    except Exception as e:
      return 0

  def recall (self):
    try:
      return self.tp / (self.tp + self.fn * 1.0)
    except Exception as e:
      return 0

#
# Base class - ReportGenerator
#
class SummaryPage:
  #
  # Name of the page
  #
  @staticmethod
  def name ():
    return 'Summary'

  #
  # Constructor
  #
  def __init__ (self):
    self._result = None
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
    self._result = Result ()
    self._weaknesses = set ()

    self._tex_name = 'summary.%s.%s' % (organizer.build_rs.GetSource (),
                     str (organizer.grainularity).split('.')[-1])

    if not wrong_checker_is_fp:
      self._tex_name += '.skip'

    self._tool_name = organizer.build_rs.GetSource ()

  #
  # Visit datapoint
  #
  def visit (self, datapoint):
    self._result.expected += datapoint.tp + datapoint.fn
    self._result.tp += datapoint.tp
    self._result.fp += datapoint.fp
    self._result.fn += datapoint.fn

    self._weaknesses.add (datapoint.weakness)

  #
  # fini
  #
  def fini (self):
    fp = open ('%s.tex' % self._tex_name, 'w')
    fp.write ("\n\centering{\section{Summary Table}}\n")
    fp.write ("\centering\n\\begin{longtable}{| p{.17\\textwidth} | p{.17\\textwidth} | p{.12\\textwidth} | p{.10\\textwidth} | p{.10\\textwidth} | p{.10\\textwidth} | p{.15\\textwidth} | p{.15\\textwidth} |} \n\\hline")
    fp.write ("\n\centering Tool & Weaknesses & Expected & TP & FP & FN & Precision & Recall \\\\ [0.5ex]")

    fp.write ("\\hline\n %s & %s & %d & %d & %d & %d & %.2f & %.2f \\\ " % (self._tool_name, len (self._weaknesses), self._result.expected, self._result.tp, self._result.fp, self._result.fn, self._result.precision (), self._result.recall ()))
    fp.write("\\hline\n\caption{Summary analysis table.}\label{tab:myfirstlongtable}\n\end{longtable}")
    fp.write ("\n\\newpage")
    fp.close ()
