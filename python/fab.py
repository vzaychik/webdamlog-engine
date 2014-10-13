#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os
import commands

#env.parallel = False

rubyPath = '/share/apps/ruby-2.1.0/bin/ruby'

dbclusterPath = os.environ["HOME"]
avidPath = dbclusterPath + "/webdamlog"
machinePath = '/state/partition2/' + os.environ["USER"]
miklau6Path = '/state/partition1/' + os.environ["USER"]
rootPathDict = { \
    'dbcluster.cs.umass.edu':dbclusterPath, \
    'avid.cs.umass.edu':avidPath, \
    'miklau1':machinePath, \
    'miklau2':machinePath, \
    'miklau3':machinePath, \
    'miklau4':machinePath, \
    'miklau5':machinePath, \
    'miklau6':miklau6Path, }

#@task
@parallel
@hosts(['dbcluster.cs.umass.edu','avid.cs.umass.edu'])
def test():
    if (env.host == 'avid.cs.umass.edu'):
        run('sleep 10.0')
    run('hostname -f')
    run('pwd')

@hosts(['dbcluster.cs.umass.edu'])
def remote_run(filename):
    with cd(os.path.join(rootPathDict['dbcluster.cs.umass.edu'], 'webdamlog-engine/python')):
        run('git pull')
        run('python %s' % filename)


@hosts(['dbcluster.cs.umass.edu'])
def refreshDB():
    with cd(os.path.join(rootPathDict['dbcluster.cs.umass.edu'], 'webdamlog-engine')):
        run('git pull')
    with cd(os.path.join(rootPathDict['dbcluster.cs.umass.edu'], 'webdamlog-exp')):
        run('svn up')
    with cd(os.path.join(rootPathDict['dbcluster.cs.umass.edu'], 'webdamlog-engine/python')):
        run('python loadBenchmark.py')

def pull_both():
    rootPath = rootPathDict[env.host]
    #with cd(os.path.join(rootPath, 'webdamlog-engine')):
    #    run('git pull')
    with cd(os.path.join(rootPath, 'webdamlog-exp')):
        run('svn up')
        
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
        run(runString)
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
