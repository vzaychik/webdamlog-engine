from peewee import *
from datetime import date
import os
import sys
from subprocess import call
import models, scenario

pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))
import itertools

def localSVNCommit( commitPath ):
    cwd = os.getcwd()
    os.chdir(commitPath)
    callString = ['svn','add','--force','.']
    call(callString)
    callString = ['svn', 'commit', '-m', """ "" """]
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

def simple():
    scenario = models.Scenario( \
        # scenID = ?? filled in later
        scenType = 'MAF', \
        numFollowers = 6*4, \
        numAggregators = 3*4, \
        aggPerFollower = 1*4, \
        policy = 'PUB', \
        numFacts = 1000, \
        valRange = 1000, \
        ruleScenario = 'UNION_OF_JOINS', \
        hosts = ['miklau1','miklau2','miklau3','miklau4','miklau5'], \
        numHosts = 4, \
        numPeersPerHost = 3*5 )
    
    # 1 + ceil(numFollower/peersPerHost) + ceil(numAggs/peersPerHost)
    
    return [scenario]


# For each set of parameters, we want to execute 6 cases, for each combination of policy (PUBLIC | PRIVATE | KNOWN) and scenario (UNION_OF_JOINS | JOIN_OF_UNIONS).

# Case 1) Performance as a function of data size. Set VAL_RANGE to 10,000 in Constants.java.  Then fix # followers=100, # aggregators=10, overlap=1, and vary # facts between 10 and 10,000 with a logarithmic step.  I expect a linear dependency between data size (x) and time to fixpoint (y) for PUBLIC and KNOWN policies, under both scenarios.

def case1():
    scenarioList = []
    
    policyList = ['PUB','PRIV','KNOWN']
    numFactsList = [1000]
    ruleScenarioList = ['UNION_OF_JOINS','JOIN_OF_UNIONS']
    
    for tup in itertools.product(policyList, numFactsList, ruleScenarioList):
        print tup
        scenario = models.Scenario( \
            # scenID = _ _ _ (filled in later)
            scenType = 'MAF', \
            numFollowers = 6, \
            numAggregators = 3, \
            aggPerFollower = 1, \
            policy = tup[0], \
            numFacts = tup[1], \
            ruleScenario = tup[2], \
            valRange = 1000, \
            hosts = ['miklau1','miklau2','miklau3','miklau4'], \
            numHosts = 4, \
            numPeersPerHost = 3 )
        scenarioList.append(scenario)
    
    return scenarioList
    
if __name__ == "__main__":

    rootPath = os.path.join(pathToRepository, 'webdamlog-exp')

    # create scenario instances
    scenarioList = case1()
    print len(scenarioList)

    # generate scenarios
    for s in scenarioList:
        scenario.generateScenarioFiles( s, rootPath )    

    localSVNCommit(rootPath)
