from peewee import *
from datetime import date
import os, time
import sys
from subprocess import call
import tempfile
import models

pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
scenarioPath = os.path.join(pathToRepository, 'webdamlog-engine/exp/MAF')
#tempPath = pathToRepository + 'webdamlog-engine/python/temp'
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))

def generateScenarioFiles( scenario ):

    # create directory with temporary name
    # tempDir = tempfile.mkdtemp(dir=scenarioPath)
    
    stamp = int(time.time()*1000)
    print stamp
    tempDir = os.path.join(scenarioPath,str(stamp))
    os.makedirs(tempDir)
    
    # write out NetAddr file
    f = open(os.path.join(tempDir,'netAddr.txt'), "w")
    for host in scenario.hosts:
        f.write(host + '\n')
    f.close()

    # construct java execution list (in format for subprocess.call)
    javaString = ['java']
    javaString.append('-cp')
    javaString.append(os.path.join(pathToRepository,'webdamlog-engine/datagen','dataGen.jar'))
    javaString.append('org.stoyanovich.webdam.datagen.Network')
    javaString.append(str(scenario.numFollowers))
    javaString.append(str(scenario.numAggregators))
    javaString.append(str(scenario.aggPerFollower))
    javaString.append(scenario.policy)
    javaString.append(str(scenario.numFacts))
    javaString.append(scenario.ruleScenario)
    javaString.append('netAddr.txt')
    javaString.append(str(scenario.numPeersPerHost))

    # execute java
    os.chdir(tempDir)
    print 'Going to run dataGen in:'
    print os.getcwd()
    call(javaString)

    # grab ID from output directories timestamps
    #res = [d for d in os.listdir(tempDir) if 'out' in d]
    # assert len(res) > 0
#     timestamp = res[0].split('_')[2]
    scenario.scenID = stamp    
    # os.rename(tempDir,os.path.join(os.path.split(tempDir)[0],str(timestamp))) # rename temDir

    # TODO push output files to git

    # save scenario model instance with timestamp
    scenario.save(force_insert=True)

    return scenario.scenID
# execute scenario
# enter execution record in database
# use fabric; at each host:
#   pull from git
#   construct ruby execution string and execute
#   push benchmark files to git when done


# LOCAL
# pull from git
# iterate through directories, check if parsed.
# if not, parse and add to database.
# parse result and enter in database


if __name__ == "__main__":

    models.setupDatabaseTest()
    generateScenarioFiles( iterate() )
#    for s in models.Scenario.select():
#        print s.scenID, s.hosts
    
    exit()