from peewee import *
from peewee import drop_model_tables
from datetime import date
import sys, os, glob, pickle
import models
from subprocess import call

pathToRepository = '/Users/miklau/Documents/Projects/Webdam'
sys.path.append(os.path.join(pathToRepository,'webdamlog-engine/python'))


#  Returns a list of Tick objects
#  filename is absolute path to benchmark file (e.g. ...benchark_time_log_aggregator1_2013-11-26 21/20/03 -0500)
#  execID is the ID of the associated execution 
def parseBenchmarkFile(filename, execID):

    # extract peerName
    peerName = os.path.split(filename)[1].split('_')[3]

    ## Open the file, read only, read all lines
    f = open(filename, "r")
    lines = f.readlines()
    f.close()

    assert len(lines)%2==0 
    count = len(lines)/2

    parsedLines = []
    for ln in lines:
        ln1 = ln.replace("\"","").replace("[","").replace("]","").replace(" ","").replace("\n","")
        lst = ln1.split(",")
        parsedLines.append(lst)

    scenarioList = []
    for i in range(count):
        t = models.Tick( \
            execID=execID, \
            peerName=peerName, \
            fileName=filename, \
            tickIndex=i,
            tickTime1=float(parsedLines[i][1]), \
            tickTime2=float(parsedLines[i][2]), \
            tickTime3=float(parsedLines[i][3]), \
            tickTime4=float(parsedLines[i][4]), \
            tickTime5=float(parsedLines[i][5]), \
            tickTime6=float(parsedLines[i][6]), \
            tickCount1=int(parsedLines[i+count][1]), \
            tickCount2=int(parsedLines[i+count][2]), \
            tickCount3=int(parsedLines[i+count][3]), \
            tickCount4=int(parsedLines[i+count][4]), \
            tickCount5=int(parsedLines[i+count][5]), \
            )
        scenarioList.append(t)

    return scenarioList


def processBenchFiles( execID, startPath):
    fList = glob.glob(os.path.join(startPath, '*'))
    for f in fList:
        print 'Parsing benchmark file %s' % f
        scenarioList = parseBenchmarkFile(f, execID)
        for s in scenarioList:
            s.save()

def processExecs( scenID, startPath):
    dirList = glob.glob(os.path.join(startPath, 'exec_*'))
    for dir in dirList:
        execID = os.path.split(dir)[1].split('_')[1]
        try:
            models.Execution.get(models.Execution.execID == execID)
            print 'Execution %s found.' % scenID
        except DoesNotExist:
            print 'Execution %s not found, adding...' % execID
            pFile = glob.glob(os.path.join(dir, '*.pckl'))[0]  # error checking ??
            with open(pFile, 'r') as f:
                newExecution = pickle.load(f)
            newExecution.save(force_insert=True)
            processBenchFiles( execID, os.path.join(dir, 'bench_files')) # only if execID added
        pass # execution exists, not processing
    

def processScenarios( scenType, startPath):
    dirList = glob.glob(os.path.join(startPath, '*'))
    for dir in dirList:
        scenID = os.path.split(dir)[1]
        try:
            models.Scenario.get(models.Scenario.scenID == scenID)
            print 'Scenario %s found.' % scenID
        except DoesNotExist:
            print 'Scenario %s not found, adding...' % scenID
            pFile = glob.glob(os.path.join(dir, '*.pckl'))[0]  # error checking ??
            with open(pFile, 'r') as f:
                newScenario = pickle.load(f)
            newScenario.save(force_insert=True)
        processExecs(scenID,dir)            
        # whether or not it exists, call processExecs( scenID?, startPath+dir)

def processScenTypes( startPath ):
    dirList = glob.glob(os.path.join(startPath, '*'))
    print dirList
    for dir in dirList:
        scenType = os.path.split(dir)[1]
        print scenType
        processScenarios(scenType, dir)

def refreshFromFileSystem( startPath ):
    os.chdir(startPath)
    callString = ['svn','up']
    call(callString)
    processScenTypes( startPath )
    
    

if __name__ == "__main__":

    models.setupDatabase(clearDatabase=True)
    refreshFromFileSystem('/Users/miklau/Documents/Projects/Webdam/webdamlog-exp')

    # execID = 1001
    # scenID = 9999
    # testDir = '/Users/miklau/Documents/Projects/Webdam/webdamlog-exp/MAF/1385513847097/exec_1385518808938/bench_files/benchark_time_log_aggregator1_2013-11-26 21:20:03 -0500'
    # l = parseBenchmarkFile(testDir,execID)
    # print l
    # exit()  ######################################################################


# LOCAL
# pull from git
# iterate through directories, check if parsed.
# if not, parse and add to database.
# parse result and enter in database
