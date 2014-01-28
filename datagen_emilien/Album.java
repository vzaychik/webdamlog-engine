package org.webdam.datagen;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Random;

import org.webdam.datagen.Constants.COL_TYPE;
import org.webdam.datagen.Constants.PEER_TYPE;
import org.webdam.datagen.Constants.POLICY;
import org.webdam.datagen.Constants.SCENARIO;

/**
 * Part 2 scenario from Julia's code.
 *
 * Example of command line to run this class (the two last arguments are
 * optional):
 *
 * java -cp datagen.jar org.webdam.datagen.Album ../network/facebook-u19-i10.txt KNOWN 10 20 netAddr.txt 3
 */
public class Album {

    /**
     * List of ip addresses of machines
     */
    public static HashMap<Integer, String> _netAddressMap = new HashMap<>();
    // a mapping from [0, numPeers) to network ids of peers
    public static HashMap<Integer, Integer> _peerIdHM = new HashMap<>();
    public static ArrayList<Peer> _peersList = new ArrayList<>();
    public static final SCENARIO SCENARIO_NAME = SCENARIO.ALBUM;

    public static void initNetAddressMap(String inFileName, int peersPerInstance, int numPeers) {
        try {
            try (BufferedReader inFP = new BufferedReader(new FileReader(inFileName))) {
                int i = 0;
                String host = "";

                // alice, bob and sue have their own instances
                while (i < 3) {
                    host = inFP.readLine().trim();
                    _netAddressMap.put(i++, host);
                }

                // the next numPeers / peersPerInstance instances are the regular peers
                int j = peersPerInstance;
                while (i < numPeers) {
                    if (j == peersPerInstance) {
                        host = inFP.readLine().trim();
                        j = 0;
                    }
                    _netAddressMap.put(i++, host);
                    j++;
                }
            }
        } catch (IOException ioe) {
            System.out.println(ioe.toString());
        }
    }

    public static void initNetAddressMap(int numPeers) {

        for (int i = 0; i < numPeers; i++) {
            _netAddressMap.put(i, "localhost");
        }
    }

    public static String peersToString(int numPeers) {

        StringBuilder res = new StringBuilder("// known peers\n");

        for (int i = 0; i < numPeers; i++) {

            String host = "localhost";
            if (Album._netAddressMap.containsKey(i)) {
                host = Album._netAddressMap.get(i);
            }
            res.append("peer ").append(_peersList.get(i).getName()).append("=").append(host).append(":").append(Constants.PORT_OFFSET + i).append(";\n");
        }
        return res.toString();
    }

    public static String peerProgramsToCSV(int numPeers, String dirPath) {

        StringBuilder res = new StringBuilder("");
        for (int i = 0; i < numPeers; i++) {
            if (i > 0) {
                res.append(",");
            }
            res.append(dirPath).append("/run_").append(_peersList.get(i).getName());
        }
        return res.toString();
    }

    /**
     * Main class to generate the text files to launch experiments.
     *
     * @param args array of arguments, see below.
     *
     * The two last arguments are optional
     * <ul>
     * <li> networkFile - network nodes / neighbors from Facebook, space-separated, one line per node
     * <li> policy - one of PUBLIC, PRIVATE, KNOWN
     * <li> numFacts - number of facts per extensional relation photos on each peer except peers alice, bob, sue
     * <li> valRange - facts in the photoAlbum relation are drawn randomly from the interval [0, valRange)
     * <li> [instanceFile] - optional argument; name of the file (on the local system) that lists names or IP addresses of the instances, one name or IP address per line
     * <li> [numPeersPerInstance] - optional argument; number of peers to place on each instance. Peers alice, bob and sue each run on a dedicated instance.  The remaining peers are placed onto shared instances.
     * </ul>
     */
    public static void main(String[] args) {

        if (args.length < 4) {
            System.out.println("Not enough arguments: Album networkFile policy numFacts valRange [instanceFile] [numPeersPerInstance]");
            System.exit(0);
        }

        try {

            StringBuilder readmeComment = new StringBuilder("");

            String networkFileName = args[0].trim();
            POLICY policy = POLICY.valueOf(args[1]);
            int numFacts = Integer.parseInt(args[2].trim());
            int valRange = Integer.parseInt(args[3].trim());

            readmeComment.append("network file=").append(networkFileName);
            readmeComment.append(", policy=").append(policy.toString());
            readmeComment.append(", # facts per relation=").append(numFacts);
            readmeComment.append(", value range=").append(valRange);

            int numPeers = 0;
            String line;
            BufferedReader inFP = new BufferedReader(new FileReader(networkFileName));

            while ((line = inFP.readLine()) != null) {

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
            while ((line = inFP.readLine()) != null) {
                String[] tmp = line.split(" ");
                int auxId = Integer.parseInt(tmp[0]);
                Peer p = _peersList.get(_peerIdHM.get(auxId));

                for (int i = 1; i < tmp.length; i++) {
                    p.addKnownPeer(_peersList.get(_peerIdHM.get(Integer.parseInt(tmp[i]))));
                }
            }
            inFP.close();

            if (args.length > 4) {
                String instanceFile = args[4].trim();
                int peersPerInstance = Integer.parseInt(args[5]);
                initNetAddressMap(instanceFile, peersPerInstance, numPeers);
            } else {
                initNetAddressMap(numPeers);
            }

            Peer alice = _peersList.get(0);
            alice.setType(PEER_TYPE.ALICE);

            Peer bob = _peersList.get(1);
            bob.setType(PEER_TYPE.BOB);

            Peer sue = _peersList.get(2);
            sue.setType(PEER_TYPE.SUE);

            Random rand = new Random();

            for (int i = 0; i < numPeers; i++) {

                Peer p = _peersList.get(i);
                p.setScenario(Constants.SCENARIO.ALBUM);

                if (p.getType().equals(PEER_TYPE.PEER)) {

                    // on peers other than alice, bob and sue, photos and tags contain data
                    Collection photos = new Collection("photos", p.getName(), COL_TYPE.EXT, 1, "img", numFacts, valRange);
                    Collection tags = new Collection("tags", p.getName(), COL_TYPE.EXT, 1, "img,tag");

                    for (String img : photos.getFacts()) {

                        for (int j = 0; j < numPeers; j++) {

                            Peer taggedPeer = _peersList.get(j);

                            if (taggedPeer.getType().equals(PEER_TYPE.SUE)) {
                                continue;
                            }

                            float rnd = rand.nextFloat();

                            if ((taggedPeer.getType().equals(Constants.PEER_TYPE.PEER)) && (rnd < Constants.PROB_OTHER_PEER_IN_PHOTO)) {

                                tags.addFact(img + ",\"" + taggedPeer.getName() + "\"");

                            } else if ((taggedPeer.getType().equals(PEER_TYPE.ALICE) || taggedPeer.getType().equals(PEER_TYPE.BOB))
                                    && (rnd < Constants.PROB_ALICE_OR_BOB_IN_PHOTO)) {
                                tags.addFact(img + ",\"" + taggedPeer.getName() + "\"");
                            }
                        }
                    }
                    p.addCollection(photos);
                    p.addCollection(tags);

                    p.addKnownPeer(sue);
                } else {
                    // on alice, bob and sue these collections are empty
                    Collection photos = new Collection("photos", p.getName(), COL_TYPE.EXT, 1, "img");
                    Collection tags = new Collection("tags", p.getName(), COL_TYPE.EXT, 1, "img,tag");
                    p.addCollection(photos);
                    p.addCollection(tags);
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
                HashMap<String, String> hostsHM = new HashMap<>();

                for (String hostName : _netAddressMap.values()) {
                    // make a directory for each instance
                    String dirName = "out_" + Album.SCENARIO_NAME + "_" + hostName + "_" + ts;
                    File outDir = new File(dirName);
                    if (!outDir.exists()) {
                        outDir.mkdir();
                        System.out.println("Output in new directory " + dirName);
                    }
                    hostsHM.put(hostName, dirName);
                }

                StringBuilder masterRules = new StringBuilder("// rules\n");

                for (Peer p : _peersList) {
                    String hostName = _netAddressMap.get(p.getId());

                    String dirName = hostsHM.get(hostName);
                    p.outputProgramToFile(readmeComment.toString(), dirName, knownPeers);

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

                    if (Constants.MASTER_ONLY_RULES) {
                        masterRules.append(p.outputRules());
                    }
                }

                if (Constants.MASTER_ONLY_RULES) {
                    // append rules to sue's program
                    String hostname = _netAddressMap.get(sue.getId());
                    String dirName = hostsHM.get(hostname);
                    String fileName = dirName + "/run_" + sue.getName();
                    try (BufferedWriter outFP = new BufferedWriter(new FileWriter(fileName, true))) {
                        outFP.write(masterRules.toString());
                    }
                }

                for (String hostName : hostsHM.keySet()) {
                    String dirName = hostsHM.get(hostName);
                    try (BufferedWriter outFP = new BufferedWriter(new FileWriter(dirName + "/XP_NOACCESS", true))) {
                        outFP.write("\n");
                    }
                }
            }

        } catch (IOException ioe) {
            System.out.println(ioe.toString());
        }
    }
}
