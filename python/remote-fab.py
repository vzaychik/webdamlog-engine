#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os, sys

rootPathDict = { \
    'dbcluster.cs.umass.edu':'/nfs/avid/users1/miklau/webdamlog', \
    'avid.cs.umass.edu':'/nfs/avid/users1/miklau/webdamlog', \
    'miklau1':'/state/partition2/miklau', \
    'miklau2':'/state/partition2/miklau', \
    'miklau3':'/state/partition2/miklau', \
    'miklau4':'/state/partition2/miklau', \
    'miklau5':'/state/partition2/miklau', }

sys.path.append(os.path.join(rootPathDict['dbcluster.cs.umass.edu'],'webdamlog-engine/python'))

env.parallel = False

@hosts(['dbcluster.cs.umass.edu'])
def run_fab():
    with cd(os.path.join(rootPathDict['dbcluster.cs.umass.edu'], 'webdamlog-engine/python')):
        run('python fab.py')

if __name__ == '__main__':

#    env.hosts=['localhost']
    execute(run_fab)
