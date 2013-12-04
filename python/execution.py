from peewee import *
from datetime import date
import time
import os, sys, time, glob, pickle
from subprocess import call
import models, driver, fab, loadBenchmark
from fabric.api import *
from fabric.tasks import execute

#database = SqliteDatabase(None)  # Create a database instance.

#pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
#scenarioPath = os.path.join(pathToRepository, 'webdamlog-exp/MAF')


# Now executed at dbcluster.cs
def executeScenario( pathToRepository, scenID, scenType, accessBool, optim1Bool, ticks, sleep ):

    stamp = int(time.time()*1000)

    # construct execution record, to be pickled
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

    # create directory for execution within scenario dir, svn add and commit
    os.makedirs(localExecPath)
    with open(os.path.join(localExecPath,str(stamp)+'.pckl'), 'w') as f:
        pickle.dump(execution, f)
    os.makedirs(os.path.join(localExecPath,'bench_files'))  # also create this directory to avoid svn conflict at peers
    driver.localSVNCommit(localScenPath)

    # inspect scenario for 'out_' directories, infer hosts
    outs = glob.glob( os.path.join(localScenPath,'out_*'))
    outKey = os.path.split(outs[0])[1].split('_')[2]
    hosts = [os.path.split(out)[1].split('_')[1] for out in outs]

    env.hosts=hosts
    env.parallel = True     # execute on each host in parallel

    # prepare parameters for ruby script
    paramString = str(ticks) + ' '
    paramString += str(sleep) + ' '
    if accessBool:
        paramString += 'access'+' '
    if (optim1Bool and accessBool):
        paramString += 'optim1'+' '

    start = time.time()
    try:
        # each host should pull latest code and latest exp
        execute(fab.pull_both)
        execute(fab.run_ruby, execPath=execPath, scenPath=scenPath, paramString=paramString, outKey=str(outKey))
        execution.success = True
    except:
        print "Execution failed:", sys.exc_info()[0]
        execution.success = False
    
    execution.runTime = time.time() - start

    # pickle object
    with open(os.path.join(localExecPath,str(stamp)+'.pckl'), 'w') as f:
        pickle.dump(execution, f)

    # refresh database for this execution
    loadBenchmark.processExecs( scenID, localScenPath)

    driver.localSVNCommit(localScenPath)
    
    return execution.execID

if __name__ == "__main__":

    rootPath = fab.rootPathDict['dbcluster.cs.umass.edu']

    runs = 3
    for scenID in [1385949809339,1385949809670,1385949810005,1385949810399,1385949810752,1385949811095]:
        for r in range(runs):
            executeScenario( rootPath, scenID, 'MAF', False, False, 20, 0.25 )
            executeScenario( rootPath, scenID, 'MAF', True, False, 20, 0.25 )
            executeScenario( rootPath, scenID, 'MAF', True, True, 20, 0.25 )
    
    # runs = 1
    # for scenID in [1385605955733]:
    #     for r in range(runs):
    #         executeScenario( scenID, 'MAF', True, True, 20, 0.01 )
