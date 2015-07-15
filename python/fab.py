#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os
import commands

#rubyPath = '/usr/local/rvm/rubies/ruby-2.2.1/bin/ruby'
rubyPath = 'ruby'

waltzPath = os.environ["HOME"]
machinePath = '/opt/webdam/'

rootPathDict = { \
    'waltz.cs.drexel.edu':waltzPath, \
    'master':machinePath, \
    'slave01':machinePath, \
    'slave02':machinePath, \
    'slave03':machinePath, \
    'slave04':machinePath, \
    'slave05':machinePath, \
    'slave06':machinePath, \
    'slave07':machinePath, \
    'slave08':machinePath, \
    'slave09':machinePath, \
    'slave10':machinePath, \
    'slave11':machinePath, \
    'slave12':machinePath, \
    'slave13':machinePath, \
    'slave14':machinePath, \
    'slave15':machinePath, \
    'slave16':machinePath, }

#@task
@parallel
@hosts(['waltz.cs.drexel.edu'])
def test():
    run('hostname -f')
    run('pwd')

@hosts(['waltz.cs.drexel.edu'])
def remote_run(filename):
    with cd(os.path.join(rootPathDict['waltz.cs.drexel.edu'], 'webdamlog-engine/python')):
        run('git pull')
        run('python %s' % filename)


@hosts(['waltz.cs.drexel.edu'])
def refreshDB():
    with cd(os.path.join(rootPathDict['waltz.cs.drexel.edu'], 'webdamlog-engine')):
        run('git pull')
    with cd(os.path.join(rootPathDict['waltz.cs.drexel.edu'], 'webdamlog-exp')):
        run('svn up')
    with cd(os.path.join(rootPathDict['waltz.cs.drexel.edu'], 'webdamlog-engine/python')):
        run('python loadBenchmark.py')

def pull_svn(scenPath):
    rootPath = rootPathDict[env.host]
    runString = 'svn up %s' % ( os.path.join(rootPath,scenPath) )
    with cd(rootPath):
        run(runString)
        
def pull_code():
    rootPath = rootPathDict[env.host]
    with cd(os.path.join(rootPath, 'webdamlog-engine')):
        run('git pull')
    
# ruby sample execution
# for end-condition execution:
# ruby ~/webdamlog_engine/bin/xp/run_access_resultcount.rb ~/Experiments/scenario_blah <access> <optim1>
# for timed-gate execution:
# ruby ~/webdamlog-engine/bin/xp/run_access.rb ~/Experiments/scenario_blah/ 100 access

def run_ruby(execPath, scenPath, paramString, outKey):
    rootPath = rootPathDict[env.host]
    runString = '%s %s %s %s' % ( \
        rubyPath, \
        os.path.join(rootPath,'webdamlog-engine/bin/xp/run_access_resultcount.rb'), \
        os.path.join(rootPath,scenPath,'out_' + env.host + '_' + outKey), \
        paramString )
    # need to be in the execution directory because benchmark files will be created there
    with cd(os.path.join(rootPath, execPath)):
        #in case a run never finishes, give it 1 hour and timeout
        #TODO: make the timeout value not hardcoded and determined more intelligently
        run(runString, timeout=3600)

def run_commit(execPath):
    rootPath = rootPathDict[env.host]
    with cd(os.path.join(rootPath, execPath)):
        run('svn add --force .')
        run("""svn commit -m '' """)        

def run_ruby_timed(execPath, scenPath, paramString, outKey, master, masterDelay):
    rootPath = rootPathDict[env.host]
    runString = '%s %s %s %s' % ( \
        rubyPath, \
        os.path.join(rootPath,'webdamlog-engine/bin/xp/run_access.rb'), \
        os.path.join(rootPath,scenPath,'out_' + env.host + '_' + outKey), \
        paramString )
    # need to be in the execution directory because benchmark files will be created there
    with cd(os.path.join(rootPath, execPath)):
        #VZM now we make sure master comes up first 
        if (env.host != master):
           run('sleep ' + str(masterDelay))
        run(runString)
        run('svn add --force .')
        run("""svn commit -m '' """)

if __name__ == '__main__':

    execute(test)
