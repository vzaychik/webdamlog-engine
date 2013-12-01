#!/usr/bin/env python

import argparse
from fabric.api import *
from fabric.tasks import execute
import os, sys
import fab


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


#@task
@hosts(['dbcluster.cs.umass.edu','avid.cs.umass.edu','miklau1.cs.umass.edu'])
def test():
    run('hostname -f')
    run('pwd')
    run('echo %s' % env.host )

@hosts(['dbcluster.cs.umass.edu'])
def refreshDB():
    with cd(os.path.join(rootPathDict['avid.cs.umass.edu'], 'webdamlog-engine')):
        run('git pull')
    with cd(os.path.join(rootPathDict['avid.cs.umass.edu'], 'webdamlog-exp')):
        run('svn up')
    with cd(os.path.join(rootPathDict['avid.cs.umass.edu'], 'webdamlog-engine/python')):
        run('python loadBenchmark.py')


def pull_both(rootPath):
    with cd(os.path.join(rootPath, 'webdamlog-engine')):
        run('git pull')
    with cd(os.path.join(rootPath, 'webdamlog-exp')):
        run('svn up')
        
# ruby sample execution
# ruby ~/webdamlog-engine/bin/xp/run_access_remote.rb ~/Experiments/scenario_blah/ 100 0.5 access

def run_ruby(execPath, scenPath, paramString, outKey):
    rootPath = rootPathDict[env.host]
    runString = 'ruby %s %s %s' % ( \
        os.path.join(rootPath,'webdamlog-engine/bin/xp/run_access_remote.rb'), \
        os.path.join(rootPath,scenPath,'out_' + env.host + '_' + outKey), \
        paramString )
    # need to be in the execution directory because benchmark files will be created there
    with cd(os.path.join(rootPath, execPath)):
        run(runString)
        run('svn add --force .')
        run("""svn commit -m '' """)

@hosts(['dbcluster.cs.umass.edu'])
def run_fab():
    run('python fab.py')

if __name__ == '__main__':

    run_fab()


        # 
        # run('git add .')
        # run("""git commit -a --allow-empty-message""")
        # run('git push origin master')
