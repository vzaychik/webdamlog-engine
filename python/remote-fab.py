#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os, sys
import fab

def run_execute():
     with cd(os.path.join(fab.rootPathDict['waltz.cs.drexel.edu'], 'webdamlog-engine/python')):
         run('git pull')
         run('python wdlexec.py')


if __name__ == '__main__':

    env.hosts=['waltz.cs.drexel.edu']    
    execute(run_execute)
