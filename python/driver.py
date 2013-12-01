from peewee import *
from datetime import date
import os
import sys
from subprocess import call
import models, scenario
pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))
import itertools

# define bunch of scenario instances: [s]

#   LOCAL
#   for each s, generate scenario
#   push

# execute each scenario, x times (use database for coordination?)
#    push benchmark files

# LOCAL
# for each execution, parse all benchmark files

# 
#
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
        numFollowers = 6, \
        numAggregators = 3, \
        aggPerFollower = 1, \
        policy = 'PUB', \
        numFacts = 100, \
        valRange = 10, \
        ruleScenario = 'UNION_OF_JOINS', \
#        hosts = ['127.0.0.1','127.0.0.2','127.0.0.3','127.0.0.4'], \
#        hosts = ['dbcluster.cs.umass.edu'] * 4, \
        hosts = ['miklau1','miklau2','miklau3','miklau4'], \
        numHosts = 4, \
        numPeersPerHost = 3 )
    
    return [scenario]


# For each set of parameters, we want to execute 6 cases, for each combination of policy (PUBLIC | PRIVATE | KNOWN) and scenario (UNION_OF_JOINS | JOIN_OF_UNIONS).

# Case 1) Performance as a function of data size. Set VAL_RANGE to 10,000 in Constants.java.  Then fix # followers=100, # aggregators=10, overlap=1, and vary # facts between 10 and 10,000 with a logarithmic step.  I expect a linear dependency between data size (x) and time to fixpoint (y) for PUBLIC and KNOWN policies, under both scenarios.

def case1():
    scenarioList = []
    
    policyList = ['PUB','PRIV','KNOWN']
    numFactsList = [500]
    ruleScenarioList = ['UNION_OF_JOINS','JOIN_OF_UNIONS']
    
    for tup in itertools.product(policyList, numFactsList, ruleScenarioList):
        print tup
        scenario = models.Scenario( \
            # scenID = ?? filled in later
            scenType = 'MAF', \
            numFollowers = 6, \
            numAggregators = 3, \
            aggPerFollower = 1, \
            policy = tup[0], \
            numFacts = tup[1], \
            ruleScenario = tup[2], \
            valRange = 500, \
            hosts = ['dbcluster.cs.umass.edu']*4, \
            numPeersPerHost = 3 )
        scenarioList.append(scenario)
    
    return scenarioList
    
if __name__ == "__main__":

#    models.setupDatabaseTest()
    rootPath = os.path.join(pathToRepository, 'webdamlog-exp')

    # create scenario instances
    scenarioList = case1()
    print len(scenarioList)
    # generate scenarios
    for s in scenarioList:
        scenario.generateScenarioFiles( s, rootPath )    
        # need to get scenario IDs back ??

    localSVNCommit(rootPath)

    # execute scenarios, multiple times?
        # need to have (execID, scenID) pairs 
    
    # loadBenchmark files
    # filename format is:  "benchark_time_log_<peername>_<date and time of start>"
    # for each (execID, scenID) pair:
    # construct path  --> scenDir = os.path.join(scenarioPath,str(scenID),'exec_'+str(stamp))
    # iterate through all benchmark files, extract peername, call loadBenchmark
    
    exit()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    