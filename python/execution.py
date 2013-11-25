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
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))

def executeScenario( scenID, accessBool, opt1Bool, ticks, sleep ):

    # create directory with temporary name
    tempDir = tempfile.mkdtemp(dir=scenarioPath)
    
    
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
    exit() ###############################################

    # execute ruby
    # does it mattet what the cwd is?
    call(javaString)

    # TODO push benchmark files to git

    # save execution model instance with timestamp
    x=scenario.save(force_insert=True)
    print x


if __name__ == "__main__":

#    models.setupDatabaseTest()
    executeScenario( iterate() )
    for s in models.Scenario.select():
        print s.scenID, s.hosts
    
    exit()