from peewee import *
from datetime import date
import time
import os, sys, time, glob, pickle
from subprocess import call
import commands
import models, driver, loadBenchmark
from fabric.api import *
from fabric.tasks import execute
import fab
import fabric
fabric.state.output['debug']=True

build = 3

# Now executed at dbcluster.cs
#
# Executes the scenario given by scenID
#
def executeScenario( pathToRepository, scenID, scenType, mode, timeToRun, masterDelay ):

    stamp = int(time.time()*1000)
    
    # construct execution record, to be pickled
    execution = models.Execution( \
        execID = stamp, \
        scenID = scenID, \
        timeToRun = timeToRun, \
        mode = mode, \
        build = build )          # numTicks is now ignored; remove 
    
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

    print localScenPath

    # inspect scenario for 'out_' directories, infer hosts
    outs =[]
    for output in  glob.glob( os.path.join(localScenPath,'out_*')):
    	outs.append(output)
    print outs
    outKey = os.path.split(outs[0])[1].split('_')[2]  # this gets common key from name of out* directories
    print outKey
    hosts = []
    masterHost = None
    for out in outs:
        extractedHostName = os.path.split(out)[1].split('_')[1]
	if (len(glob.glob(os.path.join(out,'run_master*')))) == 1:
            masterHost = extractedHostName
        if (len(glob.glob(os.path.join(out,'run_sue*')))) == 1:
            masterHost = extractedHostName
        hosts.append(extractedHostName)
    assert(masterHost != None)

    execution.success = True
    start = time.time()

    env.hosts = hosts
    env.parallel = True     # execute on each host in parallel
    try:
        execute(fab.pull_both)         # each host should pull latest code and latest exp
    except:
        print >> sys.stderr, 'Pull failed: ', sys.exc_info()[0]
        execution.success = False

    # prepare parameters for ruby script
    paramString = ''
    paramString += str(timeToRun) + ' '
    accessBool = mode & 1
    optim1Bool = mode & 2
    if accessBool:
        paramString += 'access'+' '
    if optim1Bool:
        paramString += 'optim1'+' '

    # run on all hosts
    try:
        execute(fab.run_ruby_timed, execPath=execPath, scenPath=scenPath, paramString=paramString, outKey=str(outKey), master=masterHost, masterDelay=masterDelay)
    except:
        print >> sys.stderr, 'Execution failed: ', sys.exc_info()[0]
        execution.success = False
    
    execution.runTime = time.time() - start

    # pickle object
    with open(os.path.join(localExecPath,str(stamp)+'.pckl'), 'w') as f:
        pickle.dump(execution, f)

# refresh database for this execution
#    execute(fab.pull_both)      # make sure files generated at all hosts are at dbcluster
#    loadBenchmark.processExecs( scenID, localExecPath)

    driver.localSVNCommit(localScenPath)
    
    return execution.execID

if __name__ == "__main__":

    rootPath = fab.rootPathDict['dbcluster.cs.umass.edu']
    #getting the scenId of the last generated scenario
    scenID = commands.getoutput("ls  ~/webdamlog-exp/MAF | tail -1 ")
    runs = 1
    print scenID 
    #p1 = int(p)
    #for scenID in p:
      #  for r in range(runs):
    executeScenario( rootPath, scenID, 'MAF', 0, 30, 5 )
           # executeScenario( rootPath, scenID, 'MAF', True, False, 20, 0.25 )
           # executeScenario( rootPath, scenID, 'MAF', True, True, 20, 0.25 )
    
