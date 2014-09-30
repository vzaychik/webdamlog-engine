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
import java.util.Random;

import org.stoyanovich.webdam.datagen.Constants.COL_TYPE;
import org.stoyanovich.webdam.datagen.Constants.PEER_TYPE;
import org.stoyanovich.webdam.datagen.Constants.POLICY;

/**
 * This class generates access control annotated Webdamlog programs
 * for the photo album scenario.
 * 
 * @author Julia Stoyanovich
 *
 */
public class Album {

	public static HashMap<Integer,String> _netAddressMap = new HashMap<Integer, String>();

	// a mapping from [0, numPeers) to network ids of peers
	public static HashMap<Integer,Integer> _peerIdHM = new HashMap<Integer,Integer>();
	public static ArrayList<Peer> _peersList = new ArrayList<Peer>();
        public static Random rand = new Random((new java.util.Date()).getTime());
	
	public static boolean initNetAddressMap(String inFileName, int peersPerInstance, int numPeers) {
		try {
			BufferedReader inFP = new BufferedReader(new FileReader(inFileName));
			int i=0;
			String host="";
			
			// alice, bob and sue have their own instances
			while (i<3) {
				host = inFP.readLine().trim();
				_netAddressMap.put(i++, host);
			}

			// the next numPeers / peersPerInstance instances are the regular peers
			int j=peersPerInstance;
			while (i < numPeers)  {
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
	
	public static String peersToString(int numPeers) {
		
		StringBuffer res = new StringBuffer("// known peers\n");
		
		for (int i=0; i<numPeers; i++) {
			
			String host = "localhost";
			if (Album._netAddressMap.containsKey(i)) {
				host = Album._netAddressMap.get(i);
			}
			res.append("peer " + _peersList.get(i).getName() + "=" + host + ":" + (Constants.PORT_OFFSET + i) + ";\n");
		}
		return res.toString();
	}

	public static String peerProgramsToCSV(int numPeers, String dirPath) {
		
		StringBuffer res = new StringBuffer("");
		for (int i=0; i<numPeers; i++) {
			if (i>0) {
				res.append(",");
			}
			res.append(dirPath + "/run_" + _peersList.get(i).getName());
		}
		return res.toString();
	}
	
	public static void main(String[] args) {
		
		if (args.length < 4) {
			System.out.println("Not enough arguments: Album networkFile policy numFacts valRange [instanceFile] [numPeersPerInstance]");
			System.exit(0);
		}

		try {
			StringBuffer readmeComment = new StringBuffer("");
			
			String networkFileName = args[0].trim();
			POLICY policy = POLICY.valueOf(args[1]);
			int numFacts = Integer.parseInt(args[2].trim());
			int valRange = Integer.parseInt(args[3].trim());
			
			readmeComment.append("network file=" + networkFileName);
			readmeComment.append(", policy=" + policy.toString());
			readmeComment.append(", # facts per relation=" + numFacts);
			readmeComment.append(", value range=" + valRange);
			
			int numPeers=0;
			String line;
			BufferedReader inFP = new BufferedReader(new FileReader(networkFileName));
		
			while ( (line = inFP.readLine()) != null) {
				
				System.out.println(line);
				
				String[] tmp = line.split(" ");
				int auxId = Integer.parseInt(tmp[0]);
				int id = numPeers++;
				
				_peerIdHM.put(auxId, id);
				Peer p = new Peer(id, PEER_TYPE.PEER);
				p.setAuxId(auxId);
				_peersList.add(p);
			}
			inFP.close();

			inFP = new BufferedReader(new FileReader(networkFileName));
			while ( (line = inFP.readLine()) != null) {
				String[] tmp = line.split(" ");
				int auxId = Integer.parseInt(tmp[0]);
				Peer p = _peersList.get(_peerIdHM.get(auxId));
				
				for (int i=1; i<tmp.length; i++) {
					p.addKnownPeer(_peersList.get(_peerIdHM.get(Integer.parseInt(tmp[i]))));
				}
			}
			inFP.close();
			
			if (args.length > 4) {
				String instanceFile = args[4].trim();
				int peersPerInstance = Integer.parseInt(args[5]);
				if (!initNetAddressMap(instanceFile, peersPerInstance, numPeers)) {
				    initNetAddressMap(numPeers);
				}
			} else {
				initNetAddressMap(numPeers);
			}

			Peer alice = _peersList.get(0);
			alice.setType(PEER_TYPE.ALICE);
			
			Peer bob = _peersList.get(1);
			bob.setType(PEER_TYPE.BOB);

			Peer sue = _peersList.get(2);
			sue.setType(PEER_TYPE.SUE);

			//VZM compute the size of the final result for end condition
			int resultsize = 0;

			for (int i=0; i<numPeers; i++) {
				
				Peer p = _peersList.get(i);
				p.setScenario(Constants.SCENARIO.ALBUM);
				
				if (p.getType().equals(PEER_TYPE.PEER)) {

					// on peers other than alice, bob and sue, photos and tags contain data
					Collection photos = new Collection("photos", p.getName(), COL_TYPE.EXT, 1, "img", numFacts, valRange); 
					Collection tags = new Collection("tags", p.getName(), COL_TYPE.EXT, 1, "img,tag");

					for (String img : photos.getFacts()) {
					        int imgTag = 0;
						for (int j=0; j<numPeers; j++) {
				
							Peer taggedPeer = _peersList.get(j);
				
							if (taggedPeer.getType().equals(PEER_TYPE.SUE)) {
								continue;
							}
							
							float rnd = rand.nextFloat();
						
							if ((taggedPeer.getType().equals(Constants.PEER_TYPE.PEER)) && (rnd < Constants.PROB_OTHER_PEER_IN_PHOTO)) {

								tags.addFact(img+",\""+taggedPeer.getName() + "\"");
								
							} else if ( (taggedPeer.getType().equals(PEER_TYPE.ALICE) || taggedPeer.getType().equals(PEER_TYPE.BOB)) && 
										(rnd < Constants.PROB_ALICE_OR_BOB_IN_PHOTO)) {
									tags.addFact(img+",\""+taggedPeer.getName() + "\"");
									imgTag++;
							}
						}
						if (imgTag > 1) { //both bob and alice tagged
						    resultsize++;
						}
					}						
					p.addCollection(photos);
					p.addCollection(tags);

					p.addKnownPeer(sue);
					p.addMaster(sue);
				} else {
					// on alice, bob and sue these collections are empty
					Collection photos = new Collection("photos", p.getName(), COL_TYPE.EXT, 1, "img"); 
					Collection tags = new Collection("tags", p.getName(), COL_TYPE.EXT, 1, "img,tag");
					p.addCollection(photos);
					p.addCollection(tags);
					if (p != sue) {
					    p.addMaster(sue);
					}
				}
				
				Collection album = new Collection("album", p.getName(), COL_TYPE.INT, 1, "img,peer");
				p.addCollection(album);

				Collection friends = new Collection("friends", p.getName(), COL_TYPE.EXT, 1, "peer");
				for (Peer f : p.getKnownPeers()) {
					friends.addFact("\"" + f.getName() + "\"");
				}
				p.addCollection(friends);
				
				p.setPolicy(policy);				
			}
			
			// set up sue's collections
			Collection allFriends = new Collection("all_friends", sue.getName(), COL_TYPE.INT, 1, "peer");
			sue.addCollection(allFriends);
						
			// output to program files
			String knownPeers = Album.peersToString(numPeers);

			if (Constants.DO_FILE_IO) {
					
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
					
					for (Peer p : _peersList) {
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
						// append rules to sue's program
					        //VZM - write rules to a separate file for later injection run-time
						String dirName = "out_" + _netAddressMap.get(sue.getId()) + "_" + ts; 
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
						outFP.close();
						//VZM now write out a writeable for all peers for optim1 mode
						outFP = new BufferedWriter(new FileWriter( dirName + "/writeable.wdm", true));
						for (Peer p : _peersList) {
						    String[] policyStrings = p.outputPolicy().split("\n");
						    //we only care about the write permission here so find those lines
						    for (String policyString : policyStrings) {
							if (policyString.contains(" write ")) {
							    //TODO extract the name of the relation and who
							    String relation = policyString.substring(policyString.indexOf(" ")+1, policyString.indexOf(" write")); 
							    String who = policyString.substring(policyString.indexOf("write ")+6, policyString.indexOf(";"));
							    if (who.equals("ALL")) {
								for (Peer p2 : _peersList) {
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
					}
			}
	
		} catch (IOException ioe) {
			System.out.println(ioe.toString());
		}
	}
}
