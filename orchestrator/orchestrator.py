#!/usr/bin/python

import sys
import json
import yaml
import os

from optparse import OptionParser

from config_parser import ConfigParser
from pdr import PDR
from mrr import MRR
from ssh_node import SshNode

# Constants

# Sut configurator
SUT_CONFIGURATOR = "forwarding-behaviour.cfg"
# Config file
CONFIG_FILE = "config.yaml"
# Testbed file
TESTBED_FILE = "testbed.yaml"
# key used in the testbed file
SUT_KEY = "sut"
SUT_HOME_KEY = "sut_home"
SUT_USER_KEY = "sut_user"
SUT_NAME_KEY = "sut_name"
FWD_ENGINE_KEY = "fwd"
# Results files
RESULTS_FILES = {
    'linux' :   'Linux.txt',
    'vpp'   :   'VPP.txt'
}

# Global variables

# Sut node
SUT = ""
# Sut home
SUT_HOME = ""
# Sut user
SUT_USER = ""
# Sut name
SUT_NAME = ""
# FWD ending
FWD_ENGINE = ""

# If the testbed file does not exist - we do not continue
if os.path.exists(TESTBED_FILE) == False:
  print("Error Testbed File %s Not Found" % TESTBED_FILE)
  sys.exit(-2)

# Parse function, load global variables from testbed file
with open(TESTBED_FILE) as f:
  configs = yaml.safe_load(f)
SUT = configs[SUT_KEY]
SUT_HOME = configs[SUT_HOME_KEY]
SUT_USER = configs[SUT_USER_KEY]
SUT_NAME = configs[SUT_NAME_KEY]
FWD_ENGINE = configs[FWD_ENGINE_KEY]

# Check proper setup of the global variables
if SUT == "" or SUT_HOME == "" or SUT_USER == "" or SUT_NAME == "" or FWD_ENGINE == "":
  print("Check proper setup of the global variables")
  sys.exit(0)

# Manages the orchestration of the experiments
class Orchestrator(object):

  # Run a defined experiment using the config provided as input
  @staticmethod
  def run():
    # Resume support: load any partial Linux.txt left by a prior run
    # and skip experiments that already have non-empty results.
    results = Orchestrator.loadExisting()
    if results:
      print("resume: %d experiment(s) already in %s -- skipping those" %
            (len(results), Orchestrator.OUTPUT_FILE))
    # Establish the connection with the sut
    cfg_manager = SshNode(host=SUT, name=SUT_NAME, username=SUT_USER)
    # Move to the sut home
    cfg_manager.run_command("cd %s/%s" %(SUT_HOME, FWD_ENGINE))
    # Let's parse the test plan
    parser = ConfigParser(CONFIG_FILE)
    # Run the experiments according to the test plan:
    for config in parser.get_configs():
      key = '%s-%s' %(config.experiment, config.rate)
      if results.get(key):  # non-empty -> already done
        print("skip %s (already in results)" % key)
        continue
      # Get the rate class
      rate_to_evaluate = Orchestrator.factory(config.rate)
      # Enforce the configuration
      cfg_manager.run_command("sudo bash %s %s" %(SUT_CONFIGURATOR, config.experiment))
      # Run the experiments; swallow exceptions per-experiment so a bad
      # behavior does not lose the results we already collected.
      try:
        values = rate_to_evaluate.run(config)
        results[key] = values
      except Exception as exc:
        print("Experiment %s failed: %s" % (key, exc))
        results[key] = []
      # Incremental dump so a mid-sweep crash still leaves a usable file.
      Orchestrator.dump(results)
    # Final dump
    Orchestrator.dump(results)
    return results

  @staticmethod
  def loadExisting():
    import json as _json
    try:
      with open(Orchestrator.OUTPUT_FILE) as f:
        return _json.load(f)
    except Exception:
      return {}

  # Factory method to return the proper rate
  @staticmethod
  def factory(rate):
    if rate == "pdr":
      return PDR
    elif rate == "mrr":
      return MRR
    else:
      print("Rate %s Not Supported Yet" % rate)
      sys.exit(-1)

  OUTPUT_FILE = RESULTS_FILES[FWD_ENGINE]

  # Dump the results on a file
  @staticmethod
  def dump(results):
    with open(Orchestrator.OUTPUT_FILE, 'w') as file:
     file.write(json.dumps(results))

if __name__ == '__main__':
  results = Orchestrator.run()
  print(results)
