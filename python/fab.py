#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os

env.parallel = False
#env.hosts=['dbcluster.cs.umass.edu','avid.cs.umass.edu']
#env.hosts=['dbcluster.cs.umass.edu']

rootPathDict = { \
    'dbcluster.cs.umass.edu':'/nfs/avid/users1/miklau/webdamlog', \
    'avid.cs.umass.edu':'/nfs/avid/users1/miklau/webdamlog', \
    'miklau1':'/state/partition2/miklau', \
    'miklau2':'/state/partition2/miklau', \
    'miklau3':'/state/partition2/miklau', \
    'miklau4':'/state/partition2/miklau', \
    'miklau5':'/state/partition2/miklau', }

#@task
@hosts(['dbcluster.cs.umass.edu','avid.cs.umass.edu','miklau1'])
def test():
    run('hostname -f')
    run('pwd')
#    run('echo %s' % env.host )

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
    runString = 'ruby %s %s %s' % ( \
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

    env.hosts=['localhost']
    execute(pull_both, rootPath=rootPathDict['dbcluster.cs.umass.edu'])
    execute(test)
