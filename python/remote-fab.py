#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os, sys
import fab

# @hosts(['dbcluster.cs.umass.edu'])
# def run_fab():
#     with cd(os.path.join(rootPathDict['dbcluster.cs.umass.edu'], 'webdamlog-engine/python')):
#         run('python fab.py')
# 
# @hosts(['dbcluster.cs.umass.edu'])
def run_execute():
     with cd(os.path.join(fab.rootPathDict['dbcluster.cs.umass.edu'], 'webdamlog-engine/python')):
         run('python wdlexec.py')


if __name__ == '__main__':

#    env.parallel = False

    # env.hosts=['dbcluster.cs.umass.edu']
    # execute(fab.pull_both)
    # 
    # execute(fab.remote_run, filename='execution.py')

    env.hosts=['dbcluster.cs.umass.edu']    
    execute(run_execute)