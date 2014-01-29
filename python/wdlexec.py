import ConfigParser
#from peewee import *
import os
import sys
from subprocess import call
import models, driver, execution, scenario


# input: scenList is a list of scenario model instances populated from config
# for each one, check to see if it exists, if not, create it
# in either case, return collect scenID to existing
def matchOrCreateScenario(scenList, rootPath):
    scenIDList = []
    for scen in scenList:
        try:
            scenID = models.Scenario.get( \
                models.Scenario.scenType & 
                # ..... all fields
            ).scenID
        except DoesNotExist:    # scenario was not found, create it
            scenID = generateScenarioFiles(scen, rootPath)
        scenIDList.append(scenID)
    return scenIDList


def run(configFile)

    config = ConfigParser.ConfigParser()
    config.read(configFile)

    rootPath = config.get('environment', 'rootPath')
    scenType = config.get('default', 'scenarioType')
    scenarioList = []
    
    if scenType == 'MAF':

        # set-valued parameters (space delimited in config file)
        policyList = config.get('scenarioMAF', 'policy').split(' ')
        ruleScenarioList = config.get('scenarioMAF', 'ruleScenario').split(' ')
        
        # this forms the crossproduct of all set-valued parameters
        for tup in itertools.product(policyList, ruleScenarioList):       
            print tup
            scenario = models.Scenario( \
                # scenID = _ _ _ (filled in later)
                scenType = 'MAF', \
                numFollowers = config.getint('scenarioMAF', 'numFollowers'), \
                numAggregators = config.getint('scenarioMAF', 'numAggregators'), \
                aggPerFollower = config.getint('scenarioMAF', 'aggPerFollower'), \
                policy = tup[0], \
                numFacts = config.getint('scenarioMAF', 'numFacts'), \
                ruleScenario = tup[1], \
                valRange = config.getint('scenarioMAF', 'valRange'), \
                hosts = config.get('scenarioMAF', 'hosts').split(' '), \
                numHosts = config.getint('scenarioMAF', 'numHosts'), \
                numPeersPerHost = config.getint('scenarioMAF', 'numPeersPerHost') )
            scenarioList.append(scenario)

    if scenType == 'PA':
        # TODO
        pass

    print '***  Starting to process %i scenarios...' % len(scenarioList)
    # get scenario IDs after matching or creating scenarios
    scenIDList = matchOrCreate(scenarioList, rootPath)

    # start on executions...
    # set-valued execution parameters (space delimited in config file)
    accessCList = config.get('execution', 'accessControl').split(' ')
    
    for scenID in scenIDList:   # run all the executions, for each scenID
        print 'Running executions for scenID %i' % scenID
        for tup in itertools.product(accessCList):       # not much of a crossproduct at this point (could be extended later)
            boolString = tup[0]
            accessBool = bool( boolString[0] )
            optim1Bool = bool( boolString[1] )
            execID = execution.executeScenario( rootPath, scenID, scenType, accessBool, optim1Bool, config.getint('execution', 'ticks'),  \
                             config.getfloat('execution', 'sleep'), config.getfloat('execution', 'masterDelay')   )
            print '***  Finished execution %i.' % execID
    
    print '***  Done with executions.'
    print '***  Refreshing database to reflect new executions and any new scenarios.'
    models.setupDatabase(clearDatabase=False)
    refreshFromFileSystem( os.path.join(rootPath,'webdamlog-exp'), min(scenIDList) )
    

if __name__ == "__main__":
        
    execute('exp.cfg')
    