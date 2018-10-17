from ...DataAbstractions import *

import logging
from lxml import etree
import urllib.request
import zipfile
import io

#
# Base class - ReportGenerator
#
class AppendixPage:
  #
  # Name of the page
  #
  @staticmethod
  def name ():
    return 'Appendix'

  #
  # Constructor
  #
  def __init__ (self):
    self._tex_name = None
    self._weaknesses = None
    self._catalog_url = "http://cwe.mitre.org/data/xml/cwec_v2.4.xml.zip"

  #
  # Get the name of the tex file
  #
  def tex_name (self):
    return self._tex_name

  #
  # Initialize the page - Generic
  #
  def init (self, organizer, wrong_checker_is_fp):
    self.init (organizer.build_rs.GetSource ())

  #
  # Initalize the page - Appendix-specific
  #
  def init (self, tool_name):
    self._weaknesses = set ()
    self._tex_name = 'appendix.%s' % (tool_name)


  #
  # Visit datapoint
  #
  def visit (self, datapoint):
    self._weaknesses.add (datapoint.weakness)

  #
  # fini
  #
  def fini (self):
    catalog = self.get_catalog ()
    fp = open ('%s.tex' % self._tex_name, 'w')
    fp.write ("\\begin{appendices}\n\\section{Weakness Details}")

    for weakness in sorted (self._weaknesses):
      # Use xpath to find the weakness in the catalog, catalog has the weakness number
      # as the ID whereas we have a 'CWE' prefix
      info = catalog.xpath ('Weaknesses/Weakness[@ID=%s]' % weakness[3:])
      if len (info) == 0:
        logging.warning ('Unable to find Weakness [%s] in catalog' % weakness[3:])
        continue

      self.write_appendix_entry (info[0], fp)

    fp.write ("\\end{appendices}")
    fp.close ()

  #
  # Get the catalog from NIST
  #
  def get_catalog (self):
    # NIST stores the catalog in a zip file, so we must download it,
    # extract the XML document from the zip, then load it up into
    # an lxml.etree object
    logging.info ('Downloading catalog from [%s]' % self._catalog_url)
    response = urllib.request.urlopen (self._catalog_url).add_results ()
    zip_f = zipfile.ZipFile (io.BytesIO (response))
    xml_f = zip_f.open ('cwec_v2.4.xml')
    return etree.fromstring (xml_f.add_results ())

  #
  # Write a single appendix entry
  #
  def write_appendix_entry (self, entry, fp):
      # @TODO: See if using the XSD will make this easier
      (cwe, name, abstraction, status) = entry.values ()
      target = 'CWE' + cwe

      # Write subsection and header
      fp.write ("\n\\subsection{%s}" % (target))
      fp.write ("\n\n\\begin{mdframed}[\nlinecolor=white,linewidth=2pt,% \nframetitlerule=true,%\napptotikzsetting={\\tikzset{mdfframetitlebackground/.append style={%")
      fp.write("\n\tshade,left color=white, right color=blue!20}}},\nframetitlerulecolor=blue,\nframetitlerulewidth=1pt, innertopmargin=\\topskip,")
      fp.write("\nframetitle={\hypertarget{%s}{%s} - %s},\nouterlinewidth=1.25pt\n ]\n\end{mdframed}" % (target, target, name))

      # Write description
      desc = entry.findall('Description/Description_Summary')
      for i in desc:
        fp.write ("\n\\begin{enumerate}\n\\item Description: \\newline %s" % self.remove_formatting (i.text))

      # Write extended description
      extdesc = entry.findall ('Description/Extended_Description/Text')
      if len (extdesc) != 0:
        fp.write ("\n\\item Extended Description: \\newline ")

        for i in extdesc:
          fp.write ("%s" % (self.remove_formatting (i.text)))

      # Write platforms
      platforms = entry.findall ('Applicable_Platforms/Languages/Language')
      if len (platforms) != 0:
        fp.write ("\n\\item Applicable Platforms: ")
        fp.write("\n\\begin{itemize} ")

        for i in platforms:
          if i.get('Language_Name') != 'C#':
            fp.write("\n\\item %s" % i.get ('Language_Name'))
          else:
            fp.write("\n\\item C\\#")
  
        fp.write("\n\end{itemize}")

      # Write consequences
      consequences = entry.findall ('Common_Consequences/Common_Consequence')
      if len (consequences) != 0:
        fp.write("\n\\item Common Consequences: ")
        fp.write("\n\\begin{itemize} ")

        for consequence in consequences:
          scopes = consequence.findall ('Consequence_Scope')
          impacts = consequence.findall ('Consequence_Technical_Impact')
          notes = consequence.findall ('Consequence_Note/Text')

          if len (scopes) != 0:
            fp.write ('\n\\item Consequence Scope: %s' % ', '.join ([self.remove_formatting (s.text) for s in scopes]))

          if len (impacts) != 0:
            fp.write ('\n\\item Consequence Technical Impact: %s' % ', '.join ([self.remove_formatting (i.text) for i in impacts]))

          if len (notes) != 0:
            fp.write ('\n\\item Notes: %s' % self.remove_formatting (notes[0].text))

        fp.write("\n\end{itemize}")

      # Write footer
      fp.write ("\nFor more information please see: \\newline\\url{http://cwe.mitre.org/data/definitions/%s.html} \\newline\\newline\n" % (cwe))
      fp.write("\n\\end{enumerate}\n")

  #
  # Remove formatting from the provided string
  #
  def remove_formatting (self, src):
    return src.replace ('\n', ' ').replace ('\t', '').replace ('_', ' ')
