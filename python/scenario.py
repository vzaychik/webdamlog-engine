from peewee import *
from datetime import date
import os, time
import sys, pickle
from subprocess import call
#import tempfile
import models, driver

pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))

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
    call(javaString)

    scenario.scenID = stamp    

    # TODO push output files to git

    # save scenario model instance with timestamp
    with open(os.path.join(tempDir,str(stamp)+'.pckl'), 'w') as f:
        pickle.dump(scenario, f)
    
    return scenario.scenID

if __name__ == "__main__":

    rootPath = os.path.join(pathToRepository, 'webdamlog-exp')

    scenarios = driver.simple()
    for s in scenarios:
        generateScenarioFiles( s, rootPath )
    
    driver.localSVNCommit( rootPath )
    
    exit()