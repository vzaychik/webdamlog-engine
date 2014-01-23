from peewee import *
from datetime import date
import os, time, math
import sys, pickle
from subprocess import call
#import tempfile
import models, driver

pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))

def checkScenario(s):
    masterHosts = 1
    followerHosts = math.ceil(s.numFollowers / s.numPeersPerHost)
    assert( 1 + math.ceil())
    pass

#
# Generates a scenario using Julia's java code and stores it in the filesystem.
#
def generateScenarioFiles(scenario, rootPath):
    
    stamp = int(time.time()*1000)
    tempDir = os.path.join(rootPath, scenario.scenType, str(stamp))
    os.makedirs(tempDir)
    os.chdir(tempDir)
    
    # write out NetAddr file
    f = open(os.path.join(tempDir,'netAddr.txt'), "w")
    for host in scenario.hosts:
        f.write(host + '\n')
    f.close()

    # TODO change below to cover case where scenType = PA
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
    javaString.append(str(scenario.valRange))
    javaString.append('netAddr.txt')
    javaString.append(str(scenario.numPeersPerHost))

    # execute java
    print 'Running dataGen in:'
    print os.getcwd()
    print javaString
    call(javaString)

    scenario.scenID = stamp    

    # save scenario model instance with timestamp
    with open(os.path.join(tempDir,str(stamp)+'.pckl'), 'w') as f:
        pickle.dump(scenario, f)
    
    return scenario.scenID

if __name__ == "__main__":

    # set up path
    rootPath = os.path.join(pathToRepository, 'webdamlog-exp')

    scenarios = driver.simple()  # create a list of scenario instances
    for s in scenarios:
        generateScenarioFiles( s, rootPath )    # generate each scenario
    
    driver.localSVNCommit( rootPath )   # commit the results
    
    exit()