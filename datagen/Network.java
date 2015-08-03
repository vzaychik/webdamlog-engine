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
import java.util.Random;

/**
 * This class generates access control annotated Webdamlog programs
 * for the master / aggregators / followers scenario.
 * 
 * @author Julia Stoyanovich
 *
 */
public class Network {
    
	public static HashMap<Integer,String> _netAddressMap = new HashMap<Integer, String>();
        public static Random rand = new Random((new java.util.Date()).getTime());
    
	public static boolean initNetAddressMap(String inFileName, int peersPerInstance, int numAggregators, int numFollowers) {
	  
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
		        System.out.println("WARNING: Please check your IP address file. It does not have enough hosts for the requested setup. Using localhost.");
			return false;
			//System.out.println(ioe.toString());
		} catch (NullPointerException noe) {
		        System.out.println("WARNING: Please check your IP address file. It does not have enough hosts for the requested setup. Using localhost.");
			return false;
		}
		return true;
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

    public static int computeNumberOfResults(SCENARIO scenario, ArrayList<Peer> aggregators, ArrayList<Peer> followers, boolean wdeletes ) {
		//VZM compute the final result - yuck - for end condition
		ArrayList<HashSet<String>> aggr_results = new ArrayList<HashSet<String>>();
		HashSet<String> result = new HashSet<String>();
		if (scenario == SCENARIO.UNION_OF_JOINS) {
		    for (Peer ag : aggregators) {
			//compute intersection of all followers of this aggregator
			HashSet<String> agset = new HashSet<String>();
			boolean first = true;
			for (Peer p : ag.getKnownPeers()) {
			    if (p.getType() == PEER_TYPE.FOLLOWER) {
				Collection col = p.getCollections().get(0);
				if (first) {
				    agset.addAll(col.getFacts());
				    if (wdeletes)
					agset.removeAll(col.getDeletes());
				    first = false;
				} else {
				    HashSet<String> temp = new HashSet<String>();
				    temp.addAll(col.getFacts());
				    if (wdeletes)
					temp.removeAll(col.getDeletes());
				    agset.retainAll(temp);
				}
			    }
			}
			aggr_results.add(agset);
		    }
		    //now union of all aggregators
		    for (HashSet<String> s : aggr_results) {
			result.addAll(s);
		    }
		} else if (scenario == SCENARIO.JOIN_OF_UNIONS) {
		    for (Peer ag : aggregators) {
			//compute union of all followers of this aggregator
			HashSet<String> agset = new HashSet<String>();
			for (Peer p : ag.getKnownPeers()) {
			    if (p.getType() == PEER_TYPE.FOLLOWER) {
				HashSet<String> temp = new HashSet<String>();
				temp.addAll(p.getCollections().get(0).getFacts());
				if (wdeletes)
				    temp.removeAll(p.getCollections().get(0).getDeletes());
				agset.addAll(temp);
			    }
			}
			aggr_results.add(agset);
		    }
		    //now intersection of all aggregators
		    for (HashSet<String> s : aggr_results) {
			boolean first = true;
			for (HashSet<String> st : aggr_results) {
			    if (first) {
				result.addAll(st);
				first = false;
			    } else {
				result.retainAll(st);
			    }
			}
		    }
		}
		return result.size();

	}

	public static void main(String[] args) {
		if (args.length < 9) {
			System.out.println("Not enough arguments: Network numFollowers numAggregators numAggregatorsPerFollower policy numFacts scenario valRange numExtraCols deletePercent [instanceFile] [numPeersPerInstance]");
			System.exit(1);
		}

		StringBuffer readmeComment = new StringBuffer("");
		int numFollowers = Integer.parseInt(args[0].trim()); 
		int numAggregators = Integer.parseInt(args[1].trim()); 
		int overlap = Integer.parseInt(args[2].trim()); 

		POLICY policy = POLICY.valueOf(args[3]);
		int numFacts = Integer.parseInt(args[4].trim());
		SCENARIO scenario = SCENARIO.valueOf(args[5]);
		int valRange = Integer.parseInt(args[6].trim()); 
		int numExtraCols = Integer.parseInt(args[7].trim()); 
		int deletePercent = Integer.parseInt(args[8].trim());

		String nonKeys="col0";
		for (int col=1; col<numExtraCols; col++) {
			nonKeys += ",col" + col;
		}

		readmeComment.append("# followers=" + numFollowers);
		readmeComment.append(", # aggregators=" + numAggregators);
		readmeComment.append(", # aggregators per follower=" + overlap);
		readmeComment.append(", policy=" + policy.toString());
		readmeComment.append(", # facts per relation=" + numFacts);
		readmeComment.append(", scenario=" + scenario.toString());
		readmeComment.append(", value range=" + valRange);
		readmeComment.append(", # extra cols=" + numExtraCols);
		readmeComment.append(", delete %=" + deletePercent);

		if (args.length > 9) {
			String instanceFile = args[9].trim();
			int peersPerInstance = Integer.parseInt(args[10]);
			if (!initNetAddressMap(instanceFile, peersPerInstance, numAggregators, numFollowers)) {
			    initNetAddressMap(1+numAggregators+numFollowers);
			}
		} else {
			initNetAddressMap(1+numAggregators+numFollowers);
		}

		int currentId = 0;

		Peer master = new Peer(currentId++, PEER_TYPE.MASTER);
		if (numExtraCols == 0) {
			master.addCollection(new Collection("t", master.getName(), COL_TYPE.INT, 1, "x"));
		} else {
			master.addCollection(new Collection("t", master.getName(), COL_TYPE.INT, 1, "x", nonKeys));
		}
		master.setPolicy(policy);
		master.setScenario(scenario);

		ArrayList<Peer> aggregators = new ArrayList<Peer>();
		for (int i=0; i<numAggregators; i++) {
			Peer p = new Peer(currentId++, PEER_TYPE.AGGREGATOR);
			p.addMaster(master);
			if (numExtraCols == 0) {
				master.addSlave(p);
				p.addCollection(new Collection("s", p.getName(), COL_TYPE.INT, 1, "x"));
			} else {
				master.addSlave(p, nonKeys);
				p.addCollection(new Collection("s", p.getName(), COL_TYPE.INT, 1, "x", nonKeys));
			}
			p.setPolicy(policy);
			p.setScenario(scenario);
			aggregators.add(p);
		}

		ArrayList<Peer> followers = new ArrayList<Peer>();
		for (int i=0; i<numFollowers; i++) {
			Peer p = new Peer(currentId++, PEER_TYPE.FOLLOWER);
			p.addKnownPeer(master);
			master.addKnownPeer(p);
			if (numExtraCols == 0) {
				p.addCollection(new Collection("r", p.getName(), COL_TYPE.EXT, 1, "x", numFacts, valRange));
			} else {
				p.addCollection(new Collection("r", p.getName(), COL_TYPE.EXT, 1, "x", nonKeys, numFacts, valRange));
			}
			if (deletePercent > 0) {
			    //for each peer, grab % facts for deletion
			    p.getCollectionByName("r").deleteFacts(deletePercent);
			}
			HashSet<Integer> aggsToFollow = new HashSet<Integer>();
			for (int j=0; j <aggregators.size(); j++) {
				for (int k=0; k<=overlap-1; k++) {
					if ((p.getId() + k) % numAggregators == aggregators.get(j).getId() - 1) {
						// peer p will follow the jth aggregator
						aggsToFollow.add(j);
					}
				}
			}

			for (int j=0; j <aggregators.size(); j++) {
				if (aggsToFollow.contains(j)) {
					p.addMaster(aggregators.get(j));
					if (numExtraCols == 0) {
						aggregators.get(j).addSlave(p);
					} else {
						aggregators.get(j).addSlave(p, nonKeys);
					}
					p.setPolicy(policy);
					p.setScenario(scenario);
				}
				//VZM due to left-to-right rule evaluator all aggregators need to be known to all followers
				p.addKnownPeer(aggregators.get(j));
			}

			followers.add(p);
		}

		//VZM add to followers' known peer list every follower that shares an aggregator with it
		//and add to aggregators' known peer list every other aggregator since they share one master
		for (Peer ag : aggregators) {
		    ag.addKnownPeers(aggregators);
		    ArrayList<Peer> known = new ArrayList<Peer>();
		    for (int k=0; k<=overlap-1; k++) {
			for (Peer p : followers) {
			    if ((p.getId() + k) % numAggregators == ag.getId() - 1) {
				known.add(p);
			    }
			}
		    }
		    for (int ii=0; ii<known.size(); ii++) {
			Peer p = known.get(ii);
			for (Peer p2 : known) {
			    if (p != p2) {
				p.addKnownPeer(p2);
			    }
			}
		    }
		}

		String knownPeers = Network.peersToString(numAggregators, numFollowers);
		ArrayList<Peer> allPeers = new ArrayList<Peer>();
		allPeers.add(master);
		allPeers.addAll(aggregators);
		allPeers.addAll(followers);

		int resultsize = computeNumberOfResults(scenario, aggregators, followers, false);

		if (resultsize == 0) {
		    System.out.println("This set of arguments generates an empty result set. No files will be generated.");
		    System.exit(1);
		}

		int afterdeletesize = computeNumberOfResults(scenario, aggregators, followers, true);
		
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
						outFP.write(",run_" + p.getName());
						outFP.close();
					} else {
						BufferedWriter outFP = new BufferedWriter(new FileWriter( dirName + "/XP_NOACCESS"));
						outFP.write("run_" + p.getName());
						outFP.close();
					}

					if (Constants.MASTER_ONLY_RULES) {
						masterRules.append(p.outputRules());
					}
				}

				if (Constants.MASTER_ONLY_RULES) {
					// append rules to the master's program
				        //VZM - write rules to a separate file for later injection run-time
					String dirName = "out_" + _netAddressMap.get(0) + "_" + ts; 
					String fileName = dirName + "/rules.wdm";
					BufferedWriter outFP = new BufferedWriter(new FileWriter(fileName, true));
					outFP.write(masterRules.toString());
					outFP.close();
				}

				for (String hostName : hostsHS) {
					String dirName = "out_" + hostName + "_" + ts; 
					BufferedWriter outFP = new BufferedWriter(new FileWriter( dirName + "/XP_NOACCESS", true));
					outFP.write("\n");
					//VZM write the expected final result size in number of tuples
					outFP.write(String.valueOf(resultsize));
					outFP.write("\n");
					outFP.write(String.valueOf(afterdeletesize));
					outFP.write("\n");
					outFP.close();
					//VZM now write out a writeable for all peers for optim1 mode
					outFP = new BufferedWriter(new FileWriter( dirName + "/writeable.wdm", true));
					for (Peer p : allPeers) {
					    String[] policyStrings = p.outputPolicy().split("\n");
					    //we only care about the write permission here so find those lines
					    for (String policyString : policyStrings) {
						if (policyString.contains(" write ")) {
						    //extract the name of the relation and who
						    String relation = policyString.substring(policyString.indexOf(" ")+1, policyString.indexOf(" write")); 
						    String who = policyString.substring(policyString.indexOf("write ")+6, policyString.indexOf(";"));
						    if (who.equals("ALL")) {
							for (Peer p2 : allPeers) {
							    if (p2 != p)
								outFP.write("fact writeable@" + p2.getName() + "(\"" + p.getName() + "\",\"" + relation + "_at_" + p.getName() + "\");\n");								
							}
						    } else {
							outFP.write("fact writeable@" + who + "(\"" + p.getName() + "\",\"" + relation + "_at_" + p.getName() + "\");\n");
						    }
						}
					    }
					}
					outFP.close();
					//now write the delete file for deletions
					if (deletePercent > 0) {
					    outFP = new BufferedWriter(new FileWriter( dirName + "/deletes.wdm", true));
					    for (Peer p : followers) {
						outFP.write(p.outputDeletes());
					    }
					    outFP.close();
					}
				}

			} catch (IOException ioe) {
				System.out.println(ioe.toString());
			}
			}
		}
}
