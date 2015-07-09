from peewee import *
from datetime import date
import os
import sys
import subprocess
import commands
from subprocess import call
import models, scenario

pathToRepository = commands.getoutput("echo $HOME")
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))
import itertools

def localSVNCommit( commitPath ):
    cwd = os.getcwd()
    print "Running inside Driver"
    print cwd
    os.chdir(commitPath)
    print commitPath
    callString = ['svn','add','--force','.']
    print callString
    call(callString)
    callString = ['svn', 'commit', '-m', """ "" """]
    print callString
    call(callString)
    os.chdir(cwd)

def localCommit( commitPath ):
    cwd = os.getcwd()
    os.chdir(commitPath)
    callString = ['git','add','.']
    call(callString)
    callString = ['git', 'commit', '-m', 'local commit']
    call(callString)
    callString = ['git', 'push', 'origin', 'master']
    call(callString)
    os.chdir(cwd)


def simplePA():
    scenario = models.Scenario( \
        # scenID = ?? filled in later
        scenType = 'PA', \
        policy = 'PUB', \
        networkFile = 'facebook-u19-i10.txt', \
        numFacts = 10000, \
        valRange = 1000, \
        hosts = ['slave01','slave02','slave03','slave04','slave05','slave06'], \
        numHosts = 6, \
        numPeersPerHost = 3*3 )
    
    return [scenario]


def simpleMAF(_scenType, _numFollowers, _numAggregators, _aggPerFollower, _policy, _numFacts, _valRange, _ruleScenario, _numPeers):
    scenario = models.Scenario( \
        # scenID = ?? filled in later
        scenType = _scenType, \
        numFollowers = _numFollowers, \
        numAggregators = _numAggregators, \
        aggPerFollower = _aggPerFollower, \
        policy = _policy, \
        numFacts = _numFacts, \
        valRange = _valRange, \
        numExtraCols = 6, \
        ruleScenario = _ruleScenario, \
        hosts = ['slave01','slave02','slave03','slave04','slave05','slave06'], \
        numHosts = 6, \
        numPeersPerHost = _numPeers, \
   ) 
    return [scenario]


# For each set of parameters, we want to execute 6 cases, for each combination of policy (PUBLIC | PRIVATE | KNOWN) and scenario (UNION_OF_JOINS | JOIN_OF_UNIONS).

# From Julia's experimental descriptions
# Case 1) Performance as a function of data size. Set VAL_RANGE to 10,000 in Constants.java.  Then fix # followers=100, # aggregators=10, overlap=1, and vary # facts between 10 and 10,000 with a logarithmic step.  I expect a linear dependency between data size (x) and time to fixpoint (y) for PUBLIC and KNOWN policies, under both scenarios.


# generates a list of scenario objects for  {policies} x {numFacts} x {ruleScenarios}
def case1():
    scenarioList = []
    
    policyList = ['PUB','PRIV','KNOWN']
    numFactsList = [1000]
    ruleScenarioList = ['UNION_OF_JOINS','JOIN_OF_UNIONS']
    
    for tup in itertools.product(policyList, numFactsList, ruleScenarioList):       # this iterates thru the crossproduct
        print tup
        scenario = models.Scenario( \
            # scenID = _ _ _ (filled in later)
            scenType = 'MAF', \
            numFollowers = 6*3, \
            numAggregators = 3*3, \
            aggPerFollower = 1*3, \
            policy = tup[0], \
            numFacts = tup[1], \
            ruleScenario = tup[2], \
            valRange = 1000, \
            hosts = ['slave01','slave02','slave03','slave04','slave05'], \
            numHosts = 5, \
            numPeersPerHost = 3*3 )
        scenarioList.append(scenario)
    
    return scenarioList
    
if __name__ == "__main__":

    rootPath = os.path.join(pathToRepository, '/webdamlog-exp')

    # create scenario instances
    scenarioList = case1()
    print len(scenarioList)

    # generate scenarios
    for s in scenarioList:
        newScenID =     scenario.generateScenarioFiles( s, rootPath )
        print 'Generated new scenario: ', newScenID

    localSVNCommit(rootPath)        # commit results
