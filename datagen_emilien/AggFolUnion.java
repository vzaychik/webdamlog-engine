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

import org.webdam.datagen.Constants.SCENARIO;

/**
 * Data generator to test the limit of number of peer per machines.
 *
 * Example of command line to run this class (the two last arguments are
 * optional):
 * <ul>
 * <li> java -cp datagen.jar org.webdam.datagen.AggFolUnion 10 5 2 20 50
 * </ul>
 */
public class AggFolUnion {

    /**
     * List of ip addresses of machines
     */
    public static HashMap<Integer, String> _netAddressMap = new HashMap<>();
    private static final SCENARIO SCENARIO_NAME = SCENARIO.AGGFOLUNION;

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
        int totalPeers = 1 + numAggregators + numFollowers;
        for (int i = 0; i < totalPeers; i++) {
            String relname = "follower";
            if ((i > 0) && (i <= numAggregators)) {
                relname = "aggregator";
            } else if (i == 0) {
                relname = "master";
            }
            String host = "localhost";
            if (AggregatorsFollowers._netAddressMap.containsKey(i)) {
                host = AggregatorsFollowers._netAddressMap.get(i);
            }
            res.append("peer ").append(relname).append(i).append("=").append(host).append(":").append(Constants.PORT_OFFSET + i).append(";\n");
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
            String relname = "follower" + i;
            if ((i > 0) && (i <= numAggregators)) {
                relname = "aggregator" + i;
            }
            res.append(",").append(dirPath).append("/run_").append(relname);
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
     * <li> numAggregators - number of aggregators (middle layer)
     * <li> aggregatorsPerFollower - input degree of aggregator nodes
     * <li> numFacts - number of facts per extensional relation on a follower
     * peer. This is an upper bound - facts are not guaranteed to be unique, so
     * we’ll usually end up with fewer, after duplicate elimination.
     * <li> valRange - facts in the unary relations at follower peers are drawn
     * randomly from the interval [0, valRange)
     * <li> selectivity - the percentage of facts in aggregators to propagate on
     * master
     * <li> [numRelFollowers] - number of relations per followers
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
        if (args.length < 5) {
            System.out.println("Not enough arguments: AggFolUnion numFollowers numAggregators numAggregatorsPerFollower numFacts valRange [instanceFile] [numPeersPerInstance]");
            System.exit(0);
        }
        StringBuilder readmeComment = new StringBuilder("");
        int numFollowers = Integer.parseInt(args[0].trim());
        int numAggregators = Integer.parseInt(args[1].trim());
        int overlap = Integer.parseInt(args[2].trim());
        int numFacts = Integer.parseInt(args[3].trim());
        int valRange = Integer.parseInt(args[4].trim());
        int selectivity = Integer.parseInt(args[5].trim());

        // Header comments in files
        readmeComment.append("# followers=").append(numFollowers);
        readmeComment.append(", # aggregators=").append(numAggregators);
        readmeComment.append(", # aggregators per follower=").append(overlap);
        readmeComment.append(", # facts per relation=").append(numFacts);
        readmeComment.append(", value range=").append(valRange);
        readmeComment.append(", selectivity=").append(selectivity);

        if (args.length > 6) {
            String instanceFile = args[6].trim();
            int peersPerInstance = Integer.parseInt(args[7]);
            initNetAddressMap(instanceFile, peersPerInstance, numAggregators, numFollowers);
        } else {
            initNetAddressMap(1 + numAggregators + numFollowers);
        }


        // Setup each kind of peers
        // One master with one Webdamlog collection
        int currentId = 0;
        Peer master = new Peer(currentId++, Constants.PEER_TYPE.MASTER, SCENARIO_NAME);
        master.addCollection(new Collec("m", master.getName(), Constants.COL_TYPE.INT, 0, "field"));
        // Set master and slave for each aggreagtors peers
        ArrayList<Peer> aggregators = new ArrayList<>();
        for (int i = 0; i < numAggregators; i++) {
            Peer aggPeer = new Peer(currentId++, Constants.PEER_TYPE.AGGREGATOR, SCENARIO_NAME);
            aggPeer.addMaster(master);
            master.addSlave(aggPeer);
            aggregators.add(aggPeer);
            Collec select = new Collec(
                    Constants.SELECT_REL,
                    aggPeer.getName(),
                    Constants.COL_TYPE.EXT,
                    1,
                    "field");
            aggPeer.addCollection(select);
            for (int j = 0; (float) (j) < ((float) (valRange) * ((float) (selectivity) / 100.00)); j++) {
                select.addFact("" + j);
            }
        }
        // Follower peers
        ArrayList<Peer> followers = new ArrayList<>();
        for (int i = 0; i < numFollowers; i++) {
            Peer follower = new Peer(currentId++, Constants.PEER_TYPE.FOLLOWER, SCENARIO_NAME);
            follower.addKnownPeer(master);
            // set aggregators in which to send joins
            HashSet<Peer> aggsToFollow = new HashSet<>();
            for (int k = 0; k < overlap; k++) {
                int j = (follower.getId() + k) % numAggregators;
                aggsToFollow.add(aggregators.get(j));
            }
            for (Peer aggToFollow : aggsToFollow) {
                follower.addMaster(aggToFollow);
                aggToFollow.addSlave(follower);
            }
            followers.add(follower);

            // add collection to followers to do join to send to aggregators
            for (Collec remoteColl : follower.getMasterColl()) {
                for (int k = 0; k < Constants.REL_IN_JOINS; k++) {
                    String name = "f_" + remoteColl.getName() + "_" + k;
                    follower.addCollection(
                            new Collec(
                            name,
                            follower.getName(),
                            Constants.COL_TYPE.EXT,
                            1,
                            "field",
                            numFacts,
                            valRange));
                }
            }
        }


        String knownPeers = AggregatorsFollowers.peersToString(numAggregators, numFollowers);
        ArrayList<Peer> allPeers = new ArrayList<>();
        allPeers.add(master);
        allPeers.addAll(aggregators);
        allPeers.addAll(followers);


        if (Constants.DO_FILE_IO) {
            try {
                long ts = System.currentTimeMillis();
                HashMap<String, String> hostsDirnameHM = new HashMap<>();

                for (String hostName : _netAddressMap.values()) {
                    // make a directory for each instance
                    String dirName = "out_" + AggFolUnion.SCENARIO_NAME + "_" + hostName + "_" + ts;
                    File outDir = new File(dirName);
                    if (!outDir.exists()) {
                        outDir.mkdir();
                        System.out.println("Output in new directory " + dirName);
                    }
                    hostsDirnameHM.put(hostName, dirName);
                }

                StringBuilder masterRules = new StringBuilder("// rules\n");

                for (Peer p : allPeers) {
                    String hostName = _netAddressMap.get(p.getId());

                    String dirName = hostsDirnameHM.get(hostName);
                    p.outputProgramToFile(readmeComment.toString(), dirName, knownPeers);

                    // Launcher file to start peer in order
                    File XPFile = new File(dirName + "/XP_NOACCESS");
                    if (XPFile.exists()) {
                        try (BufferedWriter outFP = new BufferedWriter(new FileWriter(dirName + "/XP_NOACCESS", true))) {
                            outFP.write(",run_" + p.getName());
                        }
                    } else {
                        try (BufferedWriter outFP = new BufferedWriter(new FileWriter(dirName + "/XP_NOACCESS"))) {
                            outFP.write("run_" + p.getName());
                        }
                    }

                    // Write rules in master node
                    if (Constants.MASTER_ONLY_RULES) {
                        masterRules.append(p.outputRules());
                    }
                }

                if (Constants.MASTER_ONLY_RULES) {
                    // append rules to the master's program
                    String hostname = _netAddressMap.get(0);
                    String dirName = hostsDirnameHM.get(hostname);
                    String fileName = dirName + "/run_master0";
                    try (BufferedWriter outFP = new BufferedWriter(new FileWriter(fileName, true))) {
                        outFP.write(masterRules.toString());
                    }
                }

                for (String hostName : hostsDirnameHM.keySet()) {
                    String dirName = hostsDirnameHM.get(hostName);
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
