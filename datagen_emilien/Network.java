package org.webdam.datagen;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import org.webdam.datagen.Constants.COL_TYPE;
import org.webdam.datagen.Constants.PEER_TYPE;
import org.webdam.datagen.Constants.POLICY;
import org.webdam.datagen.Constants.SCENARIO;

public class Network {

    /**
     * List of ip addresses of machines
     */
    public static HashMap<Integer, String> _netAddressMap = new HashMap<>();

    /**
     * Initialization of _netAddressMap.
     * <p>
     * Read the file with the list of addresses of machines. Set the first peer
     * alone on the first machine then distribute aggregators and followers
     *
     *
     * @param inFileName text file with one address per line
     * @param peersPerInstance
     * @param numAggregators
     * @param numFollowers
     */
    public static void initNetAddressMap(String inFileName, int peersPerInstance, int numAggregators, int numFollowers) {

        try (BufferedReader inFP = new BufferedReader(new FileReader(inFileName))) {
            int i = 0;

            // master is the sole peer on the first instance
            String host = inFP.readLine().trim();
            _netAddressMap.put(i++, host);

            // the next numAggregators / peersPerInstance instances are for the aggregators
            int j = peersPerInstance;
            while (i < (numAggregators + 1)) {
                if (j == peersPerInstance) {
                    host = inFP.readLine().trim();
                    j = 0;
                }
                _netAddressMap.put(i++, host);
                j++;
            }

            // the final numFollowers / peersPerInstance instances are for the followers
            j = peersPerInstance;
            while (i < (numFollowers + numAggregators + 1)) {
                if (j == peersPerInstance) {
                    host = inFP.readLine().trim();
                    j = 0;
                }
                _netAddressMap.put(i++, host);
                j++;
            }
        } catch (IOException ioe) {
            System.out.println(ioe.toString());
        }
    }

    /**
     * Initialization of _netAddressMap on localhost.
     *
     * @param numPeers
     */
    public static void initNetAddressMap(int numPeers) {

        for (int i = 0; i < numPeers; i++) {
            _netAddressMap.put(i, "localhost");
        }
    }

    /**
     * Write the peers line in Webdamlog format.
     *
     * @param numAggregators
     * @param numFollowers
     * @return
     */
    public static String peersToString(int numAggregators, int numFollowers) {

        StringBuilder res = new StringBuilder("// known peers\n");
        for (int i = 0; i < 1 + numAggregators + numFollowers; i++) {
            String name = "follower";
            if ((i > 0) && (i <= numAggregators)) {
                name = "aggregator";
            } else if (i == 0) {
                name = "master";
            }
            String host = "localhost";
            if (Network._netAddressMap.containsKey(i)) {
                host = Network._netAddressMap.get(i);
            }
            res.append("peer ").append(name).append(i).append("=").append(host).append(":").append(Constants.PORT_OFFSET + i).append(";\n");
        }
        return res.toString();
    }

    /**
     * Create the file for launcher.
     *
     * The file that list all the peers in the right order to be launched
     *
     * @param numAggregators
     * @param numFollowers
     * @param dirPath
     * @return
     */
    public static String peerProgramsToCSV(int numAggregators, int numFollowers, String dirPath) {

        StringBuilder res = new StringBuilder(dirPath + "/run_master0");
        for (int i = 1; i < 1 + numAggregators + numFollowers; i++) {
            String name = "follower" + i;
            if ((i > 0) && (i <= numAggregators)) {
                name = "aggregator" + i;
            }
            res.append(",").append(dirPath).append("/run_").append(name);
        }
        return res.toString();
    }

    /**
     * Main class to generate the text files to launch experiments.
     *
     * @param args array of arguments, see below.
     *
     * <ul>
     * <li> numFollowers - number of peers at the lowest layer
     * <li>numAggregators - number of aggregators (middle layer)
     * <li>aggregatorsPerFollower - degree of follower nodes
     * <li>policy - one of PUBLIC, PRIVATE, KNOWN
     * <li>numFacts - number of facts per extensional relation on a follower
     * peer. This is an upper bound - facts are not guaranteed to be unique, so
     * we’ll usually end up with fewer, after duplicate elimination.
     * <li>scenario - one of UNION_OF_JOINS and JOIN_OF_UNIONS
     * <li> valRange - facts in the unary relations at follower peers are drawn
     * randomly from the interval [0, valRange)
     * <li> numExtraCols - number additional of non-key columns
     * <li> [instanceFile] - optional argument; name of the file (on the local
     * system) that lists names or IP addresses of the instances, one name or IP
     * address per line
     * <li>[numPeersPerInstance] - optional argument; number of peers to place
     * on each instance. Master is on a dedicated instance, aggregators are on
     * the next numAggregators / numPeersPerInstance instances, followers are on
     * the next numFollowers / numPeersPerInstance instances. Different kinds of
     * peers are on separate instances, i.e., aggregators and followers don’t
     * mix.
     * </ul>
     */
    public static void main(String[] args) {

        // Check parameters
        if (args.length < 8) {
            System.out.println("Not enough arguments: Network numFollowers numAggregators numAggregatorsPerFollower policy numFacts scenario valRange numExtraCols [instanceFile] [numPeersPerInstance]");
            System.exit(0);
        }
        StringBuilder readmeComment = new StringBuilder("");
        int numFollowers = Integer.parseInt(args[0].trim());
        int numAggregators = Integer.parseInt(args[1].trim());
        int overlap = Integer.parseInt(args[2].trim());
        POLICY policy = POLICY.valueOf(args[3]);
        int numFacts = Integer.parseInt(args[4].trim());
        SCENARIO scenario = SCENARIO.valueOf(args[5]);
        int valRange = Integer.parseInt(args[6].trim());
        int numExtraCols = Integer.parseInt(args[7].trim());

        String nonKeys = "col0";
        for (int col = 1; col < numExtraCols; col++) {
            nonKeys += ",col" + col;
        }


        // Header comments in files
        readmeComment.append("# followers=").append(numFollowers);
        readmeComment.append(", # aggregators=").append(numAggregators);
        readmeComment.append(", # aggregators per follower=").append(overlap);
        readmeComment.append(", policy=").append(policy.toString());
        readmeComment.append(", # facts per relation=").append(numFacts);
        readmeComment.append(", scenario=").append(scenario.toString());
        readmeComment.append(", value range=").append(valRange);
        readmeComment.append(", # extra cols=").append(numExtraCols);

        if (args.length > 8) {
            String instanceFile = args[8].trim();
            int peersPerInstance = Integer.parseInt(args[9]);
            initNetAddressMap(instanceFile, peersPerInstance, numAggregators, numFollowers);
        } else {
            initNetAddressMap(1 + numAggregators + numFollowers);
        }


        // Setup each kind of peers
        // One master
        int currentId = 0;
        Peer master = new Peer(currentId++, PEER_TYPE.MASTER);
        if (numExtraCols == 0) {
            master.addCollection(new Collection("t", master.getName(), COL_TYPE.INT, 1, "x"));
        } else {
            master.addCollection(new Collection("t", master.getName(), COL_TYPE.INT, 1, "x", nonKeys));
        }
        master.setPolicy(policy);
        master.setScenario(scenario);
        // Follower peers
        ArrayList<Peer> aggregators = new ArrayList<>();
        for (int i = 0; i < numAggregators; i++) {
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
        // Aggregator peers
        ArrayList<Peer> followers = new ArrayList<>();
        for (int i = 0; i < numFollowers; i++) {
            Peer p = new Peer(currentId++, PEER_TYPE.FOLLOWER);
            p.addKnownPeer(master);
            if (numExtraCols == 0) {
                p.addCollection(new Collection("r", p.getName(), COL_TYPE.EXT, 1, "x", numFacts, valRange));
            } else {
                p.addCollection(new Collection("r", p.getName(), COL_TYPE.EXT, 1, "x", nonKeys, numFacts, valRange));
            }
            HashSet<Integer> aggsToFollow = new HashSet<>();
            for (int j = 0; j < aggregators.size(); j++) {
                for (int k = 0; k <= overlap; k++) {
                    if ((p.getId() + k) % numAggregators == aggregators.get(j).getId() - 1) {
                        // peer p will follow the jth aggregator
                        aggsToFollow.add(j);
                    }
                }
            }
            for (int j = 0; j < aggregators.size(); j++) {
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
            }
            followers.add(p);
        }


        String knownPeers = Network.peersToString(numAggregators, numFollowers);
        ArrayList<Peer> allPeers = new ArrayList<>();
        allPeers.add(master);
        allPeers.addAll(aggregators);
        allPeers.addAll(followers);

        if (Constants.DO_FILE_IO) {
            try {
                long ts = System.currentTimeMillis();
                HashSet<String> hostsHS = new HashSet<>(_netAddressMap.values());

                for (String hostName : hostsHS) {
                    // make a directory for each instance
                    String dirName = "out_" + hostName + "_" + ts;
                    File outDir = new File(dirName);
                    outDir.mkdir();
                    System.out.println("Output in " + dirName);
                }

                StringBuilder masterRules = new StringBuilder("// rules\n");

                for (Peer p : allPeers) {
                    String hostName = _netAddressMap.get(p.getId());

                    String dirName = "out_" + hostName + "_" + ts;
                    p.outputProgramToFile(readmeComment.toString(), dirName, knownPeers);

                    // Launcher file to start peer in order
                    File XPFile = new File(dirName + "/XP_NOACCESS");
                    if (XPFile.exists()) {
                        try (BufferedWriter outFP = new BufferedWriter(new FileWriter(dirName + "/XP_NOACCESS", true))) {
                            //if (Constants.FULL_PATHS) {
                            //	outFP.write("," + dirPath + "/run_" + p.getName());
                            //} else {
                            outFP.write(",run_" + p.getName());
                            //}
                        }
                    } else {
                        try (BufferedWriter outFP = new BufferedWriter(new FileWriter(dirName + "/XP_NOACCESS"))) {
                            //if (Constants.FULL_PATHS) {
                            //	outFP.write(dirPath + "/run_" + p.getName());
                            //} else {
                            outFP.write("run_" + p.getName());
                            //}
                        }
                    }

                    if (Constants.MASTER_ONLY_RULES) {
                        masterRules.append(p.outputRules());
                    }
                }

                if (Constants.MASTER_ONLY_RULES) {
                    // append rules to the master's program
                    String dirName = "out_" + _netAddressMap.get(0) + "_" + ts;
                    String fileName = dirName + "/run_master0";
                    try (BufferedWriter outFP = new BufferedWriter(new FileWriter(fileName, true))) {
                        outFP.write(masterRules.toString());
                    }
                }

                for (String hostName : hostsHS) {
                    String dirName = "out_" + hostName + "_" + ts;
                    try (BufferedWriter outFP = new BufferedWriter(new FileWriter(dirName + "/XP_NOACCESS", true))) {
                        outFP.write("\n");
                    }
                }
            } catch (IOException ioe) {
                System.out.println(ioe.toString());
            }
        }
    }
}
