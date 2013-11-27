#!/usr/bin/env python

from fabric.api import *
from fabric.tasks import execute
import os

env.parallel = False
#env.hosts=['dbcluster.cs.umass.edu','avid.cs.umass.edu']
#env.hosts=['dbcluster.cs.umass.edu']

rootPathDict = { \
    'dbcluster.cs.umass.edu':'/nfs/avid/users1/miklau/webdamlog', \
    'miklau1':'/state/partition2/miklau', \
    'miklau2':'/state/partition2/miklau', \
    'miklau3':'/state/partition2/miklau', \
    'miklau4':'/state/partition2/miklau', \
    'miklau5':'/state/partition2/miklau', }


#@task
@hosts(['dbcluster.cs.umass.edu','avid.cs.umass.edu'])
def test():
    run('hostname -f')
    run('pwd')
    run('echo %s' % env.host )


def pull_both(rootPath):
    with cd(os.path.join(rootPath, 'webdamlog-engine')):
        run('git pull')
    with cd(os.path.join(rootPath, 'webdamlog-exp')):
        run('git pull')

# ruby sample execution
# ruby ~/webdamlog-engine/bin/xp/run_access_remote.rb ~/Experiments/scenario_blah/ 100 0.5 access

def run_ruby(execPath, scenPath, paramString, outKey):
    rootPath = rootPathDict[env.host]
    runString = 'ruby %s %s %s' % ( \
        os.path.join(rootPath,'webdamlog-engine/bin/xp/run_access_remote.rb'), \
        os.path.join(rootPath,scenPath,'out_' + env.host + '_' + outKey), \
        paramString )
    print runString
    exit()
    # need to be in the execution directory because benchmark files will be created there
    with cd(os.path.join(rootPath, execPath)):
        run()

if __name__ == '__main__':
    execute(test)
#   execute(pull_both, rootPath='/nfs/avid/users1/miklau/webdamlog')