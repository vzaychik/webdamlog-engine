#!/bin/bash

#given an edge file as input (one edge per line, vertex indices separated by space)
#output connected component subnetworks
filename=$1
group=$2
year=$3
newfilename="/tmp/$(basename $1)flat"
echo $filename
echo $newfilename

webdampath=$HOME/webdamlog-engine

ruby ${webdampath}/network/makenetwork.rb $filename flat > $newfilename

java -cp ${webdampath}/datagen/dataGen.jar org.stoyanovich.webdam.datagen.CC $newfilename 100 | while read line
do
    #echo "next cc: $line"
    netsize=$(echo $line | wc -w)
    echo "size: $netsize"
    netname="${group}-u${netsize}-${year}.txt"
    echo $line | tr " " "\n" > /tmp/nodes.txt
    grep -Fwf /tmp/nodes.txt $newfilename > /tmp/makenet.txt
    ruby ${webdampath}/network/makenetwork.rb /tmp/makenet.txt > $netname
done
