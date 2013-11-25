from peewee import *
from datetime import date
import sys
sys.path.append('/Users/miklau/Documents/Projects/Webdam/PolicyGraph')
import models

def parseBenchmarkFile(filename, execID, peerName):

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
        
    for i in range(count):
        models.Tick.create( \
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
        print parsedLines[i]
        print parsedLines[i+count]

    for t in models.Tick.select():
        print t.execID, t.peerName, t.tickIndex, t.tickTime1, t.tickTime6, t.tickCount1, t.tickCount5

if __name__ == "__main__":

    models.setupDatabaseTest()
    execID = 1001
    scenID = 9999
    parseBenchmarkFile('test/benchmark_test.txt', execID, scenID )

    exit()  ######################################################################


# LOCAL
# pull from git
# iterate through directories, check if parsed.
# if not, parse and add to database.
# parse result and enter in database
