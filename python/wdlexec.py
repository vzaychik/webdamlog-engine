import ConfigParser
from peewee import *
import itertools
import os
import sys
from subprocess import call
import models, driver, execution, scenario, loadBenchmark
from time import sleep

# input: scenList is a list of scenario model instances populated from config
# for each one, check to see if it exists, if not, create it
# in either case, return collect scenID to existing
def matchOrCreateScenario(scenList, rootPath):
    scenIDList = []
    for scen in scenList:
        try:
            scenID = models.Scenario.get( \
                models.Scenario.scenType == scen.scenType, \
                models.Scenario.numFollowers == scen.numFollowers, \
                models.Scenario.numAggregators == scen.numAggregators, \
                models.Scenario.aggPerFollower == scen.aggPerFollower, \
                models.Scenario.policy == scen.policy, \
                models.Scenario.numFacts == scen.numFacts, \
                models.Scenario.ruleScenario == scen.ruleScenario, \
                models.Scenario.valRange == scen.valRange, \
                models.Scenario.numExtraCols == scen.numExtraCols, \
                models.Scenario.numHosts == scen.numHosts, \
                models.Scenario.hosts == str(scen.hosts), \
                models.Scenario.numPeersPerHost == scen.numPeersPerHost, \
                models.Scenario.networkFile == scen.networkFile \
                ).scenID
            print '***  Found matching scenario with scenID %i.' % scenID
        except DoesNotExist:    # scenario was not found, create it
            scenID = scenario.generateScenarioFiles(scen, rootPath)
            print '***  Scenario not found; created new scenario %i' % scenID
        scenIDList.append(scenID)
    return scenIDList


def run(configFile):

    config = ConfigParser.ConfigParser()
    config.read(configFile)

    rootPath = os.environ["HOME"] + "/"+ config.get('environment', 'rootPath')
    scenType = config.get('default', 'scenarioType')
    scenarioList = []
    
    if scenType == 'MAF':

        # set-valued parameters (space delimited in config file)
        policyList = config.get('scenarioMAF', 'policy').split(' ')
        ruleScenarioList = config.get('scenarioMAF', 'ruleScenario').split(' ')
        numFollowersList = config.get('scenarioMAF', 'numFollowers').split(' ')
        numAggregatorsList = config.get('scenarioMAF', 'numAggregators').split(' ')
        numAgPerFollowerList = config.get('scenarioMAF', 'aggPerFollower').split(' ')
        numFactsList = config.get('scenarioMAF', 'numFacts').split(' ')
        
        # this forms the crossproduct of all set-valued parameters
        for tup in itertools.product(policyList, ruleScenarioList, numFollowersList, numAggregatorsList, numAgPerFollowerList, numFactsList):       
            print tup
            scenario = models.Scenario( \
                # scenID = _ _ _ (filled in later)
                scenType = 'MAF', \
                numFollowers = int(tup[2]), \
                numAggregators = int(tup[3]), \
                aggPerFollower = int(tup[4]), \
                policy = tup[0], \
                numFacts = int(tup[5]), \
                ruleScenario = tup[1], \
                #valRange = config.getint('scenarioMAF', 'valRange'), \
                valRange = tup[5], \
                numExtraCols = config.getint('scenarioMAF', 'numExtraCols'), \
                numHosts = config.getint('scenarioMAF', 'numHosts'), \
                hosts = config.get('scenarioMAF', 'hosts').split(' '), \
                numPeersPerHost = config.getint('scenarioMAF', 'numPeersPerHost') )
            scenarioList.append(scenario)


    if scenType == 'PA':
        
        policyList = config.get('scenarioPA', 'policy').split(' ')
        networkFileList = config.get('scenarioPA', 'networkFile').split(' ')
        numFactsList = config.get('scenarioPA', 'numFacts').split(' ')
        
        for tup in itertools.product(policyList, networkFileList, numFactsList):
            print tup
            numf = int(tup[1].split('-')[1][1:])-3
            numh = config.getint('scenarioPA', 'numHosts')
            scenario = models.Scenario( \
                scenType = 'PA', \
                numFollowers = numf, \
                numAggregators = 0, \
                aggPerFollower = 0, \
                policy = tup[0], \
                numFacts = int(tup[2]), \
                ruleScenario = 'PA', \
                valRange = int(tup[2]), \
                numExtraCols = 0, \
                numHosts = numh, \
                hosts = config.get('scenarioPA', 'hosts').split(' '), \
                numPeersPerHost = numf/(numh-1)+1, \
                networkFile = tup[1] )
            scenarioList.append(scenario)


    print '***  Checking / creating %i scenarios...' % len(scenarioList)
    # get scenario IDs after matching or creating scenarios
    scenIDList = matchOrCreateScenario(scenarioList, rootPath)

    driver.localSVNCommit( os.path.join(rootPath, 'webdamlog-exp') )

    # start on executions...
    # set-valued execution parameters (space delimited in config file)
    accessCList = config.get('execution', 'accessControl').split(' ')
    
    for scenID in scenIDList:   # run all the executions, for each scenID
        for run in range( config.getint('execution', 'numRuns') ):
            print 'Running executions for scenID %i' % scenID
            for tup in accessCList:
                print 'the string is:', tup
                mode = int(tup,2)
                print 'mode is *****', mode
                execID = execution.executeScenario( rootPath, scenID, scenType, mode,  \
                                 config.getfloat('execution', 'timeToRun'), config.getfloat('execution', 'masterDelay')   )
                print '***  Finished run %i of execution %i.' % (run, execID)
                sleep(20) 
    print '***  Done with executions.'
    #print '***  Refreshing database to reflect new executions and any new scenarios.'
    #models.setupDatabase(clearDatabase=False)
    #loadBenchmark.refreshFromFileSystem( os.path.join(rootPath,'webdamlog-exp'), min(scenIDList) )
    

if __name__ == "__main__":
        
    run('exp.cfg')
    
