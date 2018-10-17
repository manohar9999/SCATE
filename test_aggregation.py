from lib.DataAbstractions import *
from lib.DataManagers.XMLManager import *
from lib.DataPointFactories.NIST_Cpp_DPFactory import *

def import_rs2 (filename, single_rs, merged_rs):
  m = XMLManager (filename)
  m.add_results (single_rs)
  m.add_results (merged_rs)

def import_rs1 (filename, rs):
  m = XMLManager (filename)
  m.add_results (rs)

merged_rs = ResultSet ()

tool1_rs = ResultSet ()
import_rs1 ('tests/import1.xml', tool1_rs)
import_rs1 ('tests/build1.xml', tool1_rs)

tool2_rs = ResultSet ()
import_rs1 ('tests/import2.xml', tool2_rs)
import_rs1 ('tests/build2.xml', tool2_rs)

tool3_rs = ResultSet ()
import_rs1 ('tests/import3.xml', tool3_rs)
import_rs1 ('tests/build3.xml', tool3_rs)

import1_rs = ResultSet ()
import_rs2 ('tests/import1.xml', import1_rs, merged_rs)

import2_rs = ResultSet ()
import_rs2 ('tests/import2.xml', import2_rs, merged_rs)

import3_rs = ResultSet ()
import_rs2 ('tests/import3.xml', import3_rs, merged_rs)

build1_rs = ResultSet ()
import_rs2 ('tests/build1.xml', build1_rs, merged_rs)

build2_rs = ResultSet ()
import_rs2 ('tests/build2.xml', build2_rs, merged_rs)

build3_rs = ResultSet ()
import_rs2 ('tests/build3.xml', build3_rs, merged_rs)

def validate_merge_flaws (rs):
  print (rs['CWE134']['/opt/testspace/SCATE/test-cases/NIST_Cpp/testcases/CWE134']['CWE134_Uncontrolled_Format_String__char_environment_vprintf_73b.cpp']['bad_vasink'][38].get_Flaws ())

#validate_merge_flaws (import1_rs)
#validate_merge_flaws (import2_rs)
#validate_merge_flaws (merged_rs)

def validate_merge_bugs (rs):
  print(rs['CWE134']['/opt/testspace/SCATE/test-cases/NIST_Cpp/testcases/CWE134']['CWE134_Uncontrolled_Format_String__char_environment_vprintf_73b.cpp']['bad_vasink'][38].get_Bugs ())

#validate_merge_bugs (build1_rs)
#validate_merge_bugs (build2_rs)
#validate_merge_bugs (merged_rs)

def print_dps (rs, granularity, minimum):
  factory = NIST_Cpp_DPFactory (rs)
  total = {'tp': 0, 'fp': 0, 'fn': 0}
  for dp in factory.generate (granularity, True, minimum):
    print ('%s:%s:%s - (%s:%s:%s)' % (dp.filename, dp.function, dp.line, dp.tp, dp.fp, dp.fn))
    total['tp'] += dp.tp
    total['fp'] += dp.fp
    total['fn'] += dp.fn
  print ('total: %s\n' % total)

def validate_dps_min (rs, label):
  for granularity in [Granularity.FILENAME, Granularity.FUNCTION, Granularity.LINE]:
    print ('%s DPs (%s) (min)' % (label, granularity))
    print_dps (rs, granularity, True)

def validate_dps_max (rs, label):
  for granularity in [Granularity.FILENAME, Granularity.FUNCTION, Granularity.LINE]:
    print ('%s DPs (%s) (max)' % (label, granularity))
    print_dps (rs, granularity, False)

#validate_dps_min (tool1_rs, 'Tool1')
#validate_dps_min (tool2_rs, 'Tool2')
#validate_dps_min (tool3_rs, 'Tool3')
validate_dps_min (merged_rs, 'Merged')
validate_dps_max (merged_rs, 'Merged')
