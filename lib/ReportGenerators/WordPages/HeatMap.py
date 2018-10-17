from ...DataAbstractions import *
from ..WordGenerator import Organizer

from collections import defaultdict
import logging
import re
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
import pylab

class Heat_Map:
  def __init__ (self, title, xlabel, ylabel, xticks, yticks):
    # Reset matplotlib state
    plt.figure ()

    # Force the graph size to prevent labels from overlapping
    pylab.rcParams ['figure.figsize'] = 8, 8

    # Store the axis labels
    self._yticks = sorted (yticks, reverse=True)
    self._xticks = sorted (xticks)

    self._fig, self._ax = plt.subplots ()

    # Set Labels
    self._ax.set_title (title)
    self._ax.set_xlabel (xlabel)
    self._ax.set_ylabel (ylabel)

    # Set Ticks
    x_range = np.arange (len (xticks))
    y_range = np.arange (len (yticks))
    plt.xticks (x_range, self._xticks, rotation='vertical', fontsize=10)
    plt.yticks (y_range, self._yticks, fontsize=10)

    # Initalize the data matrix
    self._data = np.empty ([len (yticks), len (xticks)], dtype='Float64')
    self._data.fill (None)

    # Register color map
    cdict = {'red': ((0.0, 1.0, 1.0),
                     (1.0, 0.0, 0.0)),

             'green': ((0.0, 0.0, 0.0),
                       (1.0, 1.0, 1.0)),

             'blue': ((0.0, 0.0, 0.0),
                      (1.0, 0.0, 0.0))}

    self._cmap = LinearSegmentedColormap('RedGreen', cdict)
    plt.register_cmap(cmap=self._cmap)

  def set (self, xtick, ytick, value):
    self._data [self._yticks.index (ytick)]\
               [self._xticks.index (xtick)] = value

  def save (self, filename):
    # Draw the graph
    cax = self._ax.imshow (self._data, aspect='auto', interpolation='nearest', cmap=self._cmap)

    # Add the legend
    cbar = self._fig.colorbar (cax, ticks=[0, 0.5, 1])
    cbar.ax.set_yticklabels (['0%', '50%', '100%'])

    # Save the image
    plt.savefig (filename, bbox_inches='tight', pad_inches=0.1)

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

  def percent_found (self):
    try:
      return (self.tp * 1.0) / (self.tp + self.fn) * 100
    except Exception as e:
      return 0

#
# Base class - ReportGenerator
#
class HeatMapPage:
  #
  # Name of the page
  #
  @staticmethod
  def name ():
    return 'HeatMap'

  #
  # Constructor
  #
  def __init__ (self):
    self._file_result = None
    self._function_result = None
    self._line_result = None
    self._result = defaultdict (Result)
    self._granularity = None
    self._permutation_re = re.compile ('.*(\d\d).*')
    self._weaknesses = set ()
    self._permutations = set ()
    self._wrong_checker_is_fp = None
    self._tool_name = None

  #
  # Initialize the page
  #
  def init (self, organizer, wrong_checker_is_fp):
    self.assign_result ()
    self._granularity = organizer.granularity
    self._result = defaultdict (Result) 
    self._wrong_checker_is_fp = wrong_checker_is_fp
    self._tool_name = organizer.build_rs.GetSource ()

  def assign_result (self):
    if self._granularity == Organizer.Granularity.FILENAME:
      self._file_result = self._result.copy ()
    elif self._granularity == Organizer.Granularity.FUNCTION:
      self._function_result = self._result.copy ()
    elif self._granularity == Organizer.Granularity.LINE:
      self._line_result = self._result.copy ()

  #
  # Visit datapoint
  #
  def visit (self, datapoint):
    # We always group by filename at least, so all flaws/bugs should
    # point to the same file.  Get the permutation.  Possible filenames are:
    # [CWE]_[Description_with_underscores]__[datatype_with_underscores]_[unknown_id]_[function/loop]_[permutation].[c|cpp]
    # [CWE]_[Description_with_underscores]__[datatype_with_underscores]_[unknown_id]_[function/loop]_[permutation][a|b].[c|cpp]
    # [CWE]_[Description_with_underscores]__[datatype_with_underscores]_[unknown_id]_[function/loop]_[permutation]_[good[B2G|G2B]|bad].[c|cpp]
    if len (datapoint.flaws) != 0:
      filename = datapoint.flaws[0].filename
    elif len (datapoint.bugs) != 0:
      filename = datapoint.bugs[0].filename
    else:
      logging.warning ('No Bugs or Flaws found for datapoint')
      return

    match = self._permutation_re.match (filename)

    if not match:
      print (repr (datapoint.directory))
      logging.warning ('Unable to extract permutation for [%s]' % filename)
      return

    permutation = match.group (1)
    target = self._result[(datapoint.weakness, permutation)]

    target.expected += datapoint.tp + datapoint.fn
    target.tp += datapoint.tp
    target.fp += datapoint.fp
    target.fn += datapoint.fn

    self._weaknesses.add (datapoint.weakness)
    self._permutations.add (permutation)

  #
  # fini
  #
  def fini (self, document):
    self.assign_result ()

    document.add_heading ('Heat Map')

    filename_prefix = self._tool_name
    if self._wrong_checker_is_fp:
      filename_prefix += '.skip'

    self.generate_image (self._file_result, '%s.filename.png' % filename_prefix)
    document.add_heading ('File Granularity', level=4)
    document.add_picture ('%s.filename.png' % filename_prefix)

    self.generate_image (self._function_result, '%s.function.png' % filename_prefix)
    document.add_heading ('Function Granularity', level=4)
    document.add_picture ('%s.function.png' % filename_prefix)

    self.generate_image (self._line_result, '%s.line.png' % filename_prefix)
    document.add_heading ('Line Granularity', level=4)
    document.add_picture ('%s.line.png' % filename_prefix)

    document.add_page_break ()

  def generate_image (self, granularity_result, filename):
    hm = Heat_Map ('', 'Weakness (CWE)', 'Permutations', self._weaknesses, self._permutations)
    for (weakness, permutation) in sorted (granularity_result):
      result = granularity_result [(weakness, permutation)]
      hm.set (weakness, permutation, result.percent_found () / 100)
    hm.save ('%s' % filename)
