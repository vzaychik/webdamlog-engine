from peewee import *
from datetime import date
import os, sys, time, glob, pickle
from subprocess import call
import models, driver, fab
from fabric.api import *
from fabric.tasks import execute

database = SqliteDatabase(None)  # Create a database instance.

pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
scenarioPath = os.path.join(pathToRepository, 'webdamlog-exp/MAF')

remotePathToRepository = '/state/partition2/miklau'
# runs locally, executes webdamlog remotely, writes to database


def executeScenario( scenID, scenType, accessBool, optim1Bool, ticks, sleep ):

    stamp = int(time.time()*1000)

    # construct execution record
    execution = models.Execution( \
        execID = stamp, \
        scenID = scenID, \
        numTicks = ticks, \
        sleep = sleep, \
        access = accessBool, \
        optim1 = optim1Bool )
    
    # this is the directory containing the scenario: e.g. webdamlog-exp/MAF/1385388824301
    scenPath = os.path.join('webdamlog-exp',scenType,str(scenID))
    
    # make sure scenario path exists locally
    localScenPath = os.path.join(pathToRepository,scenPath)
    assert os.path.exists(localScenPath)
    
    # this is the path to dir where output will be written (by remote peers later)
    # e.g. webdamlog-exp/MAF/1385388824301/exec_str99999999999d
    execPath = os.path.join(scenPath,'exec_'+str(stamp))
    localExecPath = os.path.join( os.path.join(pathToRepository,execPath))

    # create directory for execution within scenario dir, write out execution object, git add
    os.makedirs(localExecPath)
    with open(os.path.join(localExecPath,str(stamp)+'.pckl'), 'w') as f:
        pickle.dump(execution, f)
    driver.localSVNCommit(localScenPath)
#    os.chdir(localExecPath)

    outs = glob.glob( os.path.join(localScenPath,'out_*'))
    outKey = os.path.split(outs[0])[1].split('_')[2]
    hosts = [os.path.split(out)[1].split('_')[1] for out in outs]
    print outKey
    print hosts

    # at each host:
    # 1)   pull from git -- both code and exp !!
    env.parallel = True
    env.hosts=hosts
    execute(fab.pull_both, rootPath='/nfs/avid/users1/miklau/webdamlog')

    #2)   chdir to exec_
    #   execute ruby providing path to proper out_ directory based on host
    # outDir = os.path.join(scenarioPath,str(scenID),'out_localhost_1385388824526')

    paramString = str(ticks) + ' '
    paramString += str(sleep) + ' '
    if accessBool:
        paramString += 'access'+' '
    if (optim1Bool and accessBool):
        paramString += 'optim1'+' '
    
    execute(fab.run_ruby, execPath=execPath, scenPath=scenPath, paramString=paramString, outKey=str(outKey))


    # 3) push at each host

    # ruby sample execution
    # ruby ~/webdamlog-engine/bin/xp/run_access_remote.rb ~/Experiments/scenario_blah/ 100 0.5 access

    #   and put all benchmark files into bench_files folder in the directory where the script was executed from. There will be one benchmark file per peer per execution, with the following filename schema: benchark_time_log_<peername>_<date and time of start>

    return execution.execID

if __name__ == "__main__":

#    models.setupDatabaseTest()
    for r in range(5):
        execID = executeScenario( 1385569244486, 'MAF', True, True, 20, 0.1 )
    
    exit()