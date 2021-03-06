from peewee import *
from datetime import date
import os, time, math
import sys, pickle
from subprocess import call
from sys import argv
import models, driver
import subprocess
import commands
from fabric.api import *
from fabric.tasks import execute
import fab
import fabric
fabric.state.output['debug']=True


pathToRepository = commands.getoutput("echo $HOME")
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))
commitPath = os.path.join(pathToRepository,'webdamlog-exp')
print commitPath

def checkScenario(s):
    masterHosts = 1
    followerHosts = math.ceil(s.numFollowers / s.numPeersPerHost)
    assert(1 + math.ceil())
    pass

#
# Generates a scenario using Julia's java code and stores it in the filesystem.
# input: scenario is a single scenario object
# input: rootPath
def generateScenarioFiles(scenario, rootPath):
    
    stamp = int(time.time()*1000)
    tempDir = os.path.join(rootPath, 'webdamlog-exp', scenario.scenType, str(stamp))
    os.makedirs(tempDir)
    os.chdir(tempDir)
    
    # write out NetAddr file
    f = open(os.path.join(tempDir,'netAddr.txt'), "w")
    for host in scenario.hosts:
        f.write(host + '\n')
    f.close()

    # construct java execution list (in format for subprocess.call)
    javaString = ['java']
    javaString.append('-cp')
    javaString.append(os.path.join(rootPath,'webdamlog-engine/datagen','dataGen.jar'))
    if (scenario.scenType == 'MAF'): # parameters for MAF
        javaString.append('org.stoyanovich.webdam.datagen.Network')
        javaString.append(str(scenario.numFollowers))
        javaString.append(str(scenario.numAggregators))
        javaString.append(str(scenario.aggPerFollower))
        javaString.append(scenario.policy)
        javaString.append(str(scenario.numFacts))
        javaString.append(scenario.ruleScenario)
        javaString.append(str(scenario.valRange))
        javaString.append(str(scenario.numExtraCols))        
    if (scenario.scenType == 'PA'): # parameters for PA
        javaString.append('org.stoyanovich.webdam.datagen.Album')
#        javaString.append(scenario.networkFile)
        javaString.append(os.path.join(rootPath,'webdamlog-engine/network',str(scenario.networkFile)))
        javaString.append(scenario.policy)
        javaString.append(str(scenario.numFacts))
        javaString.append(str(scenario.valRange))
    # common parameters
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
    rootPath = pathToRepository
    script = argv[0]
    _scenType = argv[1]
    _numFollowers = int(argv[2])
    _numAggregators = int(argv[3])
    _aggPerFollower = int(argv[4])
    _policy = argv[5]
    _numFacts = int(argv[6])
    _valRange = int(argv[7])
    _ruleScenario = argv[8]
    _numPeers = int(argv[9])
    scenarios = driver.simpleMAF(_scenType, _numFollowers, _numAggregators, _aggPerFollower, _policy, _numFacts, _valRange, _ruleScenario, _numPeers)  # create a list of scenario instances
    for s in scenarios:
        generateScenarioFiles( s, rootPath )    # generate each scenario
    #sys.path.append(os.path.join(rootPath,'/webdamlog-exp'))
    
    driver.localSVNCommit( commitPath )   # commit the results
    
    exit()
