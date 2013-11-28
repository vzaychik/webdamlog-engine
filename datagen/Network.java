package org.stoyanovich.webdam.datagen;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import org.stoyanovich.webdam.datagen.Constants.COL_TYPE;
import org.stoyanovich.webdam.datagen.Constants.PEER_TYPE;
import org.stoyanovich.webdam.datagen.Constants.POLICY;
import org.stoyanovich.webdam.datagen.Constants.SCENARIO;

/**
 * This class generates access control annotated Webdamlog programs
 * for the master / aggregators / followers scenario.
 * 
 * @author Julia Stoyanovich
 *
 */
public class Network {

	public static HashMap<Integer,String> _netAddressMap = new HashMap<Integer, String>();
	
	public static void initNetAddressMap(String inFileName, int peersPerInstance, int numAggregators, int numFollowers) {
		try {
			BufferedReader inFP = new BufferedReader(new FileReader(inFileName));
			int i=0;
			
			// master is the sole peer on the first instance
			String host = inFP.readLine().trim();
			_netAddressMap.put(i++, host);

			// the next numAggregators / peersPerInstance instances are for the aggregators
			int j=peersPerInstance;
			while ( i < (numAggregators + 1))  {
				if (j==peersPerInstance) {
					host = inFP.readLine().trim();
					j = 0;
				}
				_netAddressMap.put(i++, host);
				j++;
			}
			
			// the final numFollowers / peersPerInstance instances are for the followers
			j=peersPerInstance;
			while ( i < (numFollowers + numAggregators + 1))  {
				if (j == peersPerInstance) {
					host = inFP.readLine().trim();
					j = 0;
				}
				_netAddressMap.put(i++, host);
				j++;
			}
			inFP.close();
		} catch (IOException ioe) {
			System.out.println(ioe.toString());
		}
	}
	
	public static void initNetAddressMap(int numPeers) {

		for (int i=0; i<numPeers; i++) {
			_netAddressMap.put(i, "localhost");
		}
	}
	
	public static String peersToString(int numAggregators, int numFollowers) {
		
		StringBuffer res = new StringBuffer("// known peers\n");
		for (int i=0; i<1+numAggregators+numFollowers; i++) {
			String name = "follower";
			if ((i>0) && (i<=numAggregators)) {
				name = "aggregator";
			} else if (i==0) {
				name = "master";
			}
			String host = "localhost";
			if (Network._netAddressMap.containsKey(i)) {
				host = Network._netAddressMap.get(i);
			}
			res.append("peer " + name + i + "=" + host + ":" + (Constants.PORT_OFFSET + i) + ";\n");
		}
		return res.toString();
	}
	
	public static String peerProgramsToCSV(int numAggregators, int numFollowers, String dirPath) {
		
		StringBuffer res = new StringBuffer(dirPath + "/run_master0");
		for (int i=1; i<1+numAggregators+numFollowers; i++) {
			String name = "follower" + i;
			if ((i>0) && (i<=numAggregators)) {
				name = "aggregator"+ i;
			}
			res.append("," + dirPath + "/run_" + name);
		}
		return res.toString();
	}
	
	public static void main(String[] args) {
		if (args.length < 7) {
			//System.out.println("Not enough arguments: Network numFollowers numAggregators numAggregatorsPerFollower policy numFacts scenario dirPath [instanceFile] [numPeersPerInstance]");
			System.out.println("Not enough arguments: Network numFollowers numAggregators numAggregatorsPerFollower policy numFacts scenario valRange [instanceFile] [numPeersPerInstance]");
			System.exit(0);
		}
		
		StringBuffer readmeComment = new StringBuffer("");
		int numFollowers = Integer.parseInt(args[0].trim()); 
		int numAggregators = Integer.parseInt(args[1].trim()); 		
		int overlap = Integer.parseInt(args[2].trim()); 
		
		POLICY policy = POLICY.valueOf(args[3]);
		int numFacts = Integer.parseInt(args[4].trim());
		SCENARIO scenario = SCENARIO.valueOf(args[5]);
		int valRange = Integer.parseInt(args[6].trim()); 
		
		
		// String dirPath = args[6].trim();
		
		readmeComment.append("# followers=" + numFollowers);
		readmeComment.append(", # aggregators=" + numAggregators);
		readmeComment.append(", # aggregators per follower=" + overlap);
		readmeComment.append(", policy=" + policy.toString());
		readmeComment.append(", # facts per relation=" + numFacts);
		readmeComment.append(", scenario=" + scenario.toString());
		readmeComment.append(", value range=" + valRange);
				
		if (args.length > 7) {
			String instanceFile = args[7].trim();
			int peersPerInstance = Integer.parseInt(args[8]);
			initNetAddressMap(instanceFile, peersPerInstance, numAggregators, numFollowers);
		} else {
			initNetAddressMap(1+numAggregators+numFollowers);
		}
		
		int currentId = 0;
		
		Peer master = new Peer(currentId++, PEER_TYPE.MASTER);
		master.addCollection(new Collection("t", master.getName(), COL_TYPE.INT, 1, "x"));
		master.setPolicy(policy);
		master.setScenario(scenario);

		ArrayList<Peer> aggregators = new ArrayList<Peer>();
		for (int i=0; i<numAggregators; i++) {
			Peer p = new Peer(currentId++, PEER_TYPE.AGGREGATOR);
			p.addMaster(master);
			master.addSlave(p);
			p.addCollection(new Collection("s", p.getName(), COL_TYPE.INT, 1, "x"));
			p.setPolicy(policy);
			p.setScenario(scenario);
			aggregators.add(p);
		}

		ArrayList<Peer> followers = new ArrayList<Peer>();
		for (int i=0; i<numFollowers; i++) {
			Peer p = new Peer(currentId++, PEER_TYPE.FOLLOWER);
			p.addKnownPeer(master);
			p.addCollection(new Collection("r", p.getName(), COL_TYPE.EXT, 1, "x", numFacts, valRange));
			
			HashSet<Integer> aggsToFollow = new HashSet<Integer>();
			for (int j=0; j <aggregators.size(); j++) {
				for (int k=0; k<=overlap; k++) {
					if ((p.getId() + k) % numAggregators == aggregators.get(j).getId() - 1) {
						// peer p will follow the jth aggregator
						aggsToFollow.add(j);
					}
				}
			}			
			
			for (int j=0; j <aggregators.size(); j++) {
				if (aggsToFollow.contains(j)) {
					p.addMaster(aggregators.get(j));
					aggregators.get(j).addSlave(p);
					p.setPolicy(policy);
					p.setScenario(scenario);					
				}
			}
			
			followers.add(p);
		}	
		
		String knownPeers = Network.peersToString(numAggregators, numFollowers);
		ArrayList<Peer> allPeers = new ArrayList<Peer>();
		allPeers.add(master);
		allPeers.addAll(aggregators);
		allPeers.addAll(followers);
			
		if (Constants.DO_FILE_IO) {
			try {
				
				long ts = System.currentTimeMillis();
				HashSet<String> hostsHS = new HashSet<String>(_netAddressMap.values());
				
				for (String hostName : hostsHS) {
					// make a directory for each instance
					String dirName = "out_" + hostName + "_" + ts; 
					File outDir = new File(dirName);
					outDir.mkdir();				
					System.out.println("Output in " + dirName);
				}
				
				StringBuffer masterRules = new StringBuffer("// rules\n");
				
				for (Peer p : allPeers) {
					String hostName = _netAddressMap.get(p.getId());
					
					String dirName = "out_" + hostName + "_" + ts; 
					p.outputProgramToFile(readmeComment.toString(), dirName, knownPeers);

					File XPFile = new File(dirName + "/XP_NOACCESS");

					if (XPFile.exists()) {
						BufferedWriter outFP = new BufferedWriter(new FileWriter( dirName + "/XP_NOACCESS", true));
						//if (Constants.FULL_PATHS) {
						//	outFP.write("," + dirPath + "/run_" + p.getName());
						//} else {
						outFP.write(",run_" + p.getName());							
						//}
						outFP.close();						
					} else {
						BufferedWriter outFP = new BufferedWriter(new FileWriter( dirName + "/XP_NOACCESS"));
						//if (Constants.FULL_PATHS) {
						//	outFP.write(dirPath + "/run_" + p.getName());
						//} else {
						outFP.write("run_" + p.getName());	
						//}
						outFP.close();
					}
					
					if (Constants.MASTER_ONLY_RULES) {
						masterRules.append(p.outputRules());
					}
				}

				if (Constants.MASTER_ONLY_RULES) {
					// append rules to the master's program
					String dirName = "out_" + _netAddressMap.get(0) + "_" + ts; 
					String fileName = dirName + "/run_master0";
					BufferedWriter outFP = new BufferedWriter(new FileWriter(fileName, true));
					outFP.write(masterRules.toString());
					outFP.close();
				}				
			
				for (String hostName : hostsHS) {
					String dirName = "out_" + hostName + "_" + ts; 
					BufferedWriter outFP = new BufferedWriter(new FileWriter( dirName + "/XP_NOACCESS", true));
					outFP.write("\n");
					outFP.close();						
				}
				
			} catch (IOException ioe) {
				System.out.println(ioe.toString());
			}
			}
		}
}
