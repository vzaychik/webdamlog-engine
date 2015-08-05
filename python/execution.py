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
from fabric.exceptions import CommandTimeout

fabric.state.output['debug']=True

build = 16

# Executes the scenario given by scenID
#
def executeScenario( pathToRepository, scenID, scenType, mode, wdelete, timeToRun, masterDelay ):

    stamp = int(time.time()*1000)
    
    # construct execution record, to be pickled
    execution = models.Execution( \
        execID = stamp, \
        scenID = scenID, \
        timeToRun = timeToRun, \
        mode = mode, \
        wdelete = wdelete, \
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
        execute(fab.pull_svn, scenPath=scenPath)         # each host should pull latest code and latest exp
    except:
        print >> sys.stderr, 'Pull failed: ', sys.exc_info()[0]
        execution.success = False

    #only try to run ruby if the pull of files worked
    if execution.success == True:
        # prepare parameters for ruby script
        paramString = ''
        print "the mode which is set is",  mode
        accessBool = mode & 1
        optim1Bool = mode & 2
        optim2Bool = mode & 4
        if (accessBool):
            paramString += 'access'+' '
        if (optim1Bool):
            paramString += 'optim1'+' '
        if (optim2Bool):
            paramString += 'optim2'+' '
        if (wdelete):
            paramString += 'deletes'+' '
            
        # run on all hosts
        try:
            execute(fab.run_ruby, execPath=execPath, scenPath=scenPath, paramString=paramString, outKey=str(outKey))
        except CommandTimeout:
            execution.success = False
            #delete the tmp file that was used for shutdown
            with settings(warn_only=True):
                execute(fab.clean_tmp)
            #don't want to check the files in, this run is invalid
            return        
        except:
            print >> sys.stderr, 'Execution failed: ', sys.exc_info()[0]
            execution.success = False

        #delete the tmp file that was used for shutdown
        with settings(warn_only=True):
            execute(fab.clean_tmp)

        try:
            execute(fab.run_commit, execPath=execPath)
        except:
            print >> sys.stderr, 'Failed to commit files, please add them manually: ', sys.exc_info()[0]
            #this does not change the execution success
    
    execution.runTime = time.time() - start

    # pickle object
    with open(os.path.join(localExecPath,str(stamp)+'.pckl'), 'w') as f:
        pickle.dump(execution, f)

# refresh database for this execution
#    execute(fab.pull_svn)      # make sure files generated at all hosts are in
#    loadBenchmark.processExecs( scenID, localExecPath)

    driver.localSVNCommit(localScenPath)
    
    return execution.execID

if __name__ == "__main__":

    rootPath = fab.rootPathDict['waltz.cs.drexel.edu']
    #getting the scenId of the last generated scenario
    scenID = commands.getoutput("ls  ~/webdamlog-exp/MAF | tail -1 ")
    runs = 5
    print scenID 
    #p1 = int(p)
    #for scenID in p:
      #  for r in range(runs):
    executeScenario( rootPath, scenID, 'MAF', 1, 0, 60, 0 )
           # executeScenario( rootPath, scenID, 'MAF', True, False, 20, 0.25 )
           # executeScenario( rootPath, scenID, 'MAF', True, True, 20, 0.25 )
    print "clearing the dB....."
    models.setupDatabase(clearDatabase=False)
    print "Entering the loadbenchmark ......."
    loadBenchmark.refreshFromFileSystem( os.path.join(rootPath,'webdamlog-exp'), scenID ) 
