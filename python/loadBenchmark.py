from peewee import *
from peewee import drop_model_tables
from datetime import date
import sys, os, glob, pickle
import models, fab
import subprocess
import commands
from subprocess import call

pathToRepository = commands.getoutput("echo $HOME")
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

# helper function for refreshFromFileSystem
def processBenchFiles( execID, startPath):
    print "Inside processBenchFiles....."
    fList = glob.glob(os.path.join(startPath, '*'))
    for f in fList:
        try:
            peername = os.path.split(f)[1].split('_')[3]
            #print peername
            models.Tick.get( (models.Tick.execID == execID) & (models.Tick.peerName == peername) ) # check for at least one tick with (execID, peername)
            print 'Found record for benchmark file %s' % f
        except DoesNotExist:
            print 'Parsing and adding from benchmark file %s' % f
            tickList = parseBenchmarkFile(f, execID)
            for t in tickList:
                t.save()

# helper function for refreshFromFileSystem
def processExecs( scenID, startPath):
    dirList = glob.glob(os.path.join(startPath, 'exec_*'))
    for dir in dirList:
        execID = os.path.split(dir)[1].split('_')[1]
        #print execID
	try:
            models.Execution.get(models.Execution.execID == execID)
            print 'Execution %s found.' % scenID
        except DoesNotExist:
            print 'Execution %s not found, adding...' % execID
            pFile = glob.glob(os.path.join(dir, '*.pckl'))[0]  # error checking ??
            with open(pFile, 'r') as f:
                newExecution = pickle.load(f)
            newExecution.save(force_insert=True)
        processBenchFiles( execID, os.path.join(dir, 'bench_files')) # whether or not it exists, process bench files inside
        # pass # execution exists, not processing
    
# helper function for refreshFromFileSystem
def processScenarios( scenType, startPath, siLowerBound):
    dirList = glob.glob(os.path.join(startPath, '*'))
    for dir in dirList:
        scenID = os.path.split(dir)[1]
        #print scenID
        if int(scenID) >= siLowerBound:  # test condition of scenID -- skip if less than bound
            try:
                print "entered try block"
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

# helper function for refreshFromFileSystem
def processScenTypes( startPath, siLowerBound ):
    dirList = glob.glob(os.path.join(startPath, '*'))
    #print dirList
    for dir in dirList:
        scenType = os.path.split(dir)[1]
        print scenType
        processScenarios(scenType, dir, siLowerBound)

# traverses the filesystem adding everything it finds to the database (as long as it doesn't already exist)
# if siLowerbound = k it ignores all scenarios with scenID < k.  
# use siLowerbound = 0 for everything
def refreshFromFileSystem( startPath, siLowerBound ):
    #print startPath
    #print siLowerBound
    siLowerBound = int(siLowerBound)
    os.chdir(startPath)
    callString = ['svn','up']
    call(callString)
    processScenTypes( startPath, siLowerBound )
    
if __name__ == "__main__":

    # for dbcluster running
    models.setupDatabase(clearDatabase=False)
    refreshFromFileSystem(os.path.join(fab.rootPathDict['dbcluster.cs.umass.edu'],'webdamlog-exp'), 1400000000000)
