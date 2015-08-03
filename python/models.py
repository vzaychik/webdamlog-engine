from peewee import *
from peewee import drop_model_tables
from datetime import date
import os
import commands

database = MySQLDatabase("webdamlog", host="localhost", port=3306, user="webdam", passwd="ilovedb")

class BaseModel(Model):
    class Meta:
        database = database

class Scenario(BaseModel):
    scenID = BigIntegerField(primary_key=True)
    scenType = CharField(null=True) # MAF or PA
    numFollowers = IntegerField(null=True)  # numFollowers - number of peers at the lowest layer
    numAggregators = IntegerField(null=True) # numAggregators - number of aggregators (middle layer)
    aggPerFollower = IntegerField(null=True) # aggregatorsPerFollower - degree of follower nodes
    policy = CharField(null=True) # policy - one of PUBLIC, PRIVATE, KNOWN
    numFacts = IntegerField(null=True) # numFacts - number of facts per extensional relation on a follower peer.  
    percentDelete = IntegerField(null=True) # percentDelete - the percent of facts deleted per extensional relation on a follower peer.
    ruleScenario = CharField(null=True) # scenario - one of UNION_OF_JOINS and JOIN_OF_UNIONS
    valRange = IntegerField(null=True) #facts at follower peers are drawn randomly from the interval [0, valRange)
    numExtraCols = IntegerField(null=True) #number additional of non-key columns
    numHosts = IntegerField(null=True)  # number of hosts
    hosts = CharField(null=True) # optional argument; name of the file (on the local system) that lists names or IP addresses of the instances, one name or IP address per line
    numPeersPerHost = IntegerField(null=True)
    networkFile = CharField(null=True) 

class Execution(BaseModel):
    execID = BigIntegerField(primary_key=True)
    scenID = ForeignKeyField(Scenario)
    timeToRun = FloatField()
    mode = IntegerField()
    wdelete = BooleanField()
    runTime = FloatField()
    success = BooleanField()
    build = IntegerField()

class Tick(BaseModel):
    execID = ForeignKeyField(Execution)
    peerName = CharField(null=True)     # description of peer that is benchmarked
    fileName = CharField(null=True)     # filename containing benchmarking of ticks
    tickIndex = IntegerField(null=True) # index of the tick
    tickTime1 = FloatField(null=True)    # first tick processing
    tickTime2 = FloatField(null=True)    # read from channel, rewrite strata, do wiring
    tickTime3 = FloatField(null=True)    # bootstrap or invalidate tables as necessary
    tickTime4 = FloatField(null=True)    # main processing (running until fixpoint)
    tickTime5 = FloatField(null=True)    # write on channel
    tickTime6 = FloatField(null=True)    # end of tick
    tickCount1 = IntegerField(null=True) # number of tuples across all peer non-system collections
    tickCount2 = IntegerField(null=True) # number of "words" 
    tickCount3 = IntegerField(null=True) # number of collections this peer is delegating to other peers (intermediary relations)
    tickCount4 = IntegerField(null=True) # number of rules this peer is delegating to other peers
    tickCount5 = IntegerField(null=True) # number of tuples this peer is sending to other peers
        
def setupDatabaseTest():
    pathToRepository = commands.getoutput("echo $HOME")
    database.init( os.path.join(pathToRepository,'webdamlog-engine/python/test/test.sqlite'))
    
    if not Scenario.table_exists():
        Scenario.create_table()
    if not Execution.table_exists():
        Execution.create_table()
    if not Tick.table_exists():
        Tick.create_table()

def setupDatabase(clearDatabase):
    if clearDatabase:
        drop_model_tables([Tick, Execution, Scenario])
        
    if not Scenario.table_exists():
        Scenario.create_table()
    if not Execution.table_exists():
        Execution.create_table()
    if not Tick.table_exists():
        Tick.create_table()

if __name__ == "__main__":

    setupDatabase(False)    
    database.connect()
    exit()
