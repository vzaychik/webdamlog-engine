from peewee import *
from datetime import date
import os
import sys
from subprocess import call
import tempfile
import models

database = SqliteDatabase(None)  # Create a database instance.

pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
scenarioPath = os.path.join(pathToRepository, 'webdamlog-engine/exp/MAF')

def executeScenario( scenID, accessBool, optim1Bool, ticks, sleep ):

    stamp = int(time.time()*1000)
    print stamp

    execution = models.Execution( \
        execID = stamp, \
        scenID = scenID, \
        numTicks = ticks, \
        sleep = sleep, \
        access = accessBook, \
        optim1 = optim1Bool )

    
    scenDir = os.path.join(scenarioPath,str(scenID),'exec_'+str(stamp))
    os.makedirs(scenDir)
    os.chdir(scenDir)
    
    # ruby sample execution
    # ruby ~/webdamlog-engine/bin/xp/run_access_remote.rb ~/Experiments/scenario_blah/ 100 0.5 access

    # TODO use fabric to send to remote instances
    #   pull from git

    # temporary local execution
    # construct ruby execution list (in format for subprocess.call)
    rubyList = ['ruby']
    rubyList.append( os.path.join(pathToRepository,'webdamlog-engine/bin/xp/run_access_remote.rb') )
    rubyList.append( os.path.join(scenarioPath,str(scenID)) )
    rubyList.append(str(ticks))
    rubyList.append(str(sleep))
    if accessBool:
        rubyList.append('access')
    if (opt1Bool and accessBool):
        rubyList.append('optim1')

    print rubyList
    
    #   and put all benchmark files into bench_files folder in the directory where the script was executed from. There will be one benchmark file per peer per execution, with the following filename schema: benchark_time_log_<peername>_<date and time of start>
    
    
    
    exit() ###############################################

    # execute ruby
    # does it mattet what the cwd is?
    call(rubyList)

    # TODO push benchmark files to git

    # save execution model instance with timestamp
    execution.save(force_insert=True)
    return execution.execID

if __name__ == "__main__":

#    models.setupDatabaseTest()
    executeScenario( iterate() )
    for s in models.Scenario.select():
        print s.scenID, s.hosts
    
    exit()