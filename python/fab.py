#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os

#env.parallel = False

#rubyPath = '/share/apps/ruby-2.1.0/bin/ruby'
rubyPath = 'ruby'

rootPathDict = { \
    'dbcluster.cs.umass.edu':'/nfs/avid/users1/miklau/webdamlog', \
    'avid.cs.umass.edu':'/nfs/avid/users1/miklau/webdamlog', \
    'miklau1':'/state/partition2/miklau', \
    'miklau2':'/state/partition2/miklau', \
    'miklau3':'/state/partition2/miklau', \
    'miklau4':'/state/partition2/miklau', \
    'miklau5':'/state/partition2/miklau', }

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
    with cd(os.path.join(rootPath, 'webdamlog-engine')):
        run('git pull')
    with cd(os.path.join(rootPath, 'webdamlog-exp')):
        run('svn up')
        
# ruby sample execution
# ruby ~/webdamlog-engine/bin/xp/run_access_remote.rb ~/Experiments/scenario_blah/ 100 0.5 access

def run_ruby(execPath, scenPath, paramString, outKey, master, masterDelay):
    rootPath = rootPathDict[env.host]
    runString = '%s %s %s %s' % ( \
        rubyPath, \
        os.path.join(rootPath,'webdamlog-engine/bin/xp/run_access_remote.rb'), \
        os.path.join(rootPath,scenPath,'out_' + env.host + '_' + outKey), \
        paramString )
    # need to be in the execution directory because benchmark files will be created there
    with cd(os.path.join(rootPath, execPath)):
        if (env.host == master):
            run('sleep ' + str(masterDelay))
        run(runString)
        run('svn add --force .')
        run("""svn commit -m '' """)

if __name__ == '__main__':

    execute(test)
