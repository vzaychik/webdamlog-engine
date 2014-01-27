package org.webdam.datagen;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;

import org.webdam.datagen.Constants.COL_TYPE;
import org.webdam.datagen.Constants.PEER_TYPE;
import org.webdam.datagen.Constants.POLICY;
import org.webdam.datagen.Constants.SCENARIO;

public class Peer {

    private int _id;
    private int _auxId;
    private PEER_TYPE _type;
    private POLICY _policy;
    private SCENARIO _scenario;
    private ArrayList<Peer> _masters;
    private ArrayList<Peer> _slaves;
    private HashSet<Peer> _knownPeers;
    private ArrayList<Collection> _collections;

    public Peer(int id, PEER_TYPE type) {
        _id = id;
        _auxId = id;
        _type = type;
        _slaves = new ArrayList<>();
        _masters = new ArrayList<>();
        _knownPeers = new HashSet<>();
        _collections = new ArrayList<>();
    }

    public void setAuxId(int auxId) {
        _auxId = auxId;
    }

    public int getAuxId() {
        return _auxId;
    }

    public PEER_TYPE getType() {
        return _type;
    }

    public void setType(PEER_TYPE type) {
        _type = type;
    }

    public int getId() {
        return _id;
    }

    public String getName() {
        return _type.toString().toLowerCase() + _auxId;
    }

    public String getAddress() {
        String host = "localhost";
        if (Network._netAddressMap.containsKey(_id)) {
            host = Network._netAddressMap.get(_id);
        }
        return host + ":" + (Constants.PORT_OFFSET + _id);
    }

    public ArrayList<Collection> getCollections() {
        return _collections;
    }

    public Collection getCollectionByName(String name) {
        for (Collection c : _collections) {
            if (c.getName().equalsIgnoreCase(name)) {
                return c;
            }
        }
        return null;
    }

    public void addMaster(Peer p) {
        _masters.add(p);
        _knownPeers.add(p);
    }

    public void addSlave(Peer p) {
        _slaves.add(p);
        _knownPeers.add(p);
        if (_type.equals(PEER_TYPE.AGGREGATOR)) {
            _collections.add(new Collection("r" + p.getId(), this.getName(), COL_TYPE.INT, 1, "x"));
        } else if (_type.equals(PEER_TYPE.MASTER)) {
            _collections.add(new Collection("s" + p.getId(), this.getName(), COL_TYPE.INT, 1, "x"));
        }
    }

    public void addSlave(Peer p, String nonKeys) {
        _slaves.add(p);
        _knownPeers.add(p);
        if (_type.equals(PEER_TYPE.AGGREGATOR)) {
            _collections.add(new Collection("r" + p.getId(), this.getName(), COL_TYPE.INT, 1, "x", nonKeys));
        } else if (_type.equals(PEER_TYPE.MASTER)) {
            _collections.add(new Collection("s" + p.getId(), this.getName(), COL_TYPE.INT, 1, "x", nonKeys));
        }
    }

    public void addKnownPeer(Peer p) {
        _knownPeers.add(p);
    }

    public HashSet<Peer> getKnownPeers() {
        return _knownPeers;
    }

    /**
     * Declare a new collection for this peer
     *
     * @param c
     */
    public void addCollection(Collection c) {
        _collections.add(c);
    }

    public void setPolicy(POLICY policy) {
        _policy = policy;
    }

    public void setScenario(SCENARIO scenario) {
        _scenario = scenario;
    }

    public String outputKnownPeers() {
        StringBuilder prog = new StringBuilder("// known peers\n");
        for (Peer p : _knownPeers) {
            prog.append("peer ").append(p.getName()).append("=").append(p.getAddress()).append(";\n");
        }
        return prog.toString();
    }

    public String outputCollections() {
        StringBuilder prog = new StringBuilder("// collections\n");
        for (Collection c : _collections) {
            prog.append("collection ").append(c.getType().toString()).append(c.isPersistentToString()).append(c.getSchema()).append(";\n");
        }
        return prog.toString();
    }

    public String outputFacts() {
        StringBuilder prog = new StringBuilder("// facts\n");
        for (Collection c : _collections) {
            for (String fact : c.getFacts()) {
                prog.append("fact ").append(c.getName()).append(c.getSuffix()).append("@").append(this.getName()).append("(").append(fact).append(");\n");
            }
        }
        return prog.toString();
    }

    public String outputPolicy() {
        StringBuilder prog = new StringBuilder("// access control policy\n");
        if (_policy == POLICY.PUB) {
            for (Collection c : _collections) {
                prog.append("policy ").append(c.getName()).append(c.getSuffix()).append(" read ALL;\n");
                prog.append("policy ").append(c.getName()).append(c.getSuffix()).append(" write ALL;\n");
            }
        } else if (_policy == POLICY.KNOWN) {
            for (Collection c : _collections) {
                for (Peer p : _knownPeers) {
                    prog.append("policy ").append(c.getName()).append(c.getSuffix()).append(" read ").append(p.getName()).append(";\n");
                    prog.append("policy ").append(c.getName()).append(c.getSuffix()).append(" write ").append(p.getName()).append(";\n");
                }
            }
        }
        return prog.toString();
    }

    public String outputRules() {

        StringBuilder prog = new StringBuilder("");
        if (!Constants.MASTER_ONLY_RULES) {
            prog.append("// rules\n");
        }

        if (_scenario == SCENARIO.UNION_OF_JOINS) {

            if (_type == PEER_TYPE.MASTER) {
                // no rules
            } else if (_type == PEER_TYPE.AGGREGATOR) {

                // send the contents of relation s@thispeer(x) to relation t@master(x), on each master
                for (Peer m : _masters) {
                    Collection headC = m.getCollectionByName("t");
                    Collection bodyC = this.getCollectionByName("s");
                    prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyC.getSchemaWithVars()).append(";\n");
                }

                // take the join of r@follower_i(x*), store result in s@aggregator(x*)
                Collection headC = this.getCollectionByName("s");
                String bodyOfJoinRule = "";
                for (Peer f : _slaves) {
                    Collection bodyC = f.getCollectionByName("r");
                    if (bodyOfJoinRule.length() > 0) {
                        bodyOfJoinRule += ", ";
                    }
                    bodyOfJoinRule += bodyC.getSchemaWithVars();
                }
                prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyOfJoinRule).append(";\n");

            } else if (_type == PEER_TYPE.FOLLOWER) {
                // no rules
            }

        } else if (_scenario == SCENARIO.JOIN_OF_UNIONS) {

            if (_type == PEER_TYPE.MASTER) {

                // take the join of s@aggregator_i(x*), store result in t@master(x*)
                Collection headC = this.getCollectionByName("t");
                String bodyOfJoinRule = "";
                for (Peer f : _slaves) {
                    Collection bodyC = f.getCollectionByName("s");
                    if (bodyOfJoinRule.length() > 0) {
                        bodyOfJoinRule += ", ";
                    }
                    bodyOfJoinRule += bodyC.getSchemaWithVars();
                }
                prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyOfJoinRule).append(";\n");

            } else if (_type == PEER_TYPE.AGGREGATOR) {
                // no rules
            } else if (_type == PEER_TYPE.FOLLOWER) {
                // send the contents of relation r@thispeer(x) into s@aggregator(x), for each aggregator
                for (Peer m : _masters) {
                    Collection headC = m.getCollectionByName("s");
                    Collection bodyC = this.getCollectionByName("r");
                    prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyC.getSchemaWithVars()).append(";\n");
                }
            }
        } else if (_scenario == SCENARIO.ALBUM) {

            if (_type == PEER_TYPE.SUE) {
                Peer alice = Album._peersList.get(0);
                Peer bob = Album._peersList.get(1);

                // compute a union of friends@alice and friends@bob, store in all_friends@sue
                Collection allFriends = this.getCollectionByName("all_friends");
                Collection friendsAlice = alice.getCollectionByName("friends");
                Collection friendsBob = bob.getCollectionByName("friends");
                prog.append("rule ").append(allFriends.getSchemaWithVars()).append(" :- ").append(friendsAlice.getSchemaWithVars()).append(";\n");
                prog.append("rule ").append(allFriends.getSchemaWithVars()).append(" :- ").append(friendsBob.getSchemaWithVars()).append(";\n");

                // compute the contents of album@sue($img,$peer)
                Collection album = this.getCollectionByName("album");
                prog.append("rule ").append(album.getSchemaWithVars()).append(" :- ").append(allFriends.getSchemaWithVars()).append(", photos@$peer($img), tags@$peer($img,\"").append(alice.getName()).append("\"), tags@$peer($img,\"").append(bob.getName()).append("\");\n");
            }
        }


        return prog.toString();
    }

    public String outputProgram() {
        StringBuilder prog = new StringBuilder("// peer " + this.getName() + "\n");
        prog.append(outputKnownPeers());
        prog.append(outputCollections());
        prog.append(outputPolicy());
        prog.append(outputFacts());

        if (!Constants.MASTER_ONLY_RULES) {
            prog.append(outputRules());
        }

        return prog.toString();
    }

    public String outputProgram(String knownPeers) {
        StringBuilder prog = new StringBuilder("// peer " + this.getName() + "\n");
        prog.append(knownPeers);
        prog.append(outputCollections());
        prog.append(outputPolicy());
        prog.append(outputFacts());

        if (!Constants.MASTER_ONLY_RULES) {
            prog.append(outputRules());
        }

        return prog.toString();
    }

    public void outputProgramToFile(String comment, String outDir) throws IOException {
        String fileName = outDir + "/run_" + this.getName();
        try (BufferedWriter outFP = new BufferedWriter(new FileWriter(fileName))) {
            outFP.write("// " + comment + "\n\n");
            outFP.write(outputProgram());
        }
    }

    /**
     * Output comments + Webdamlog program for that peer into a file.
     *
     * @param comment
     * @param outDir
     * @param knownPeers
     * @throws IOException
     */
    public void outputProgramToFile(String comment, String outDir, String knownPeers) throws IOException {
        String fileName = outDir + "/run_" + this.getName();
        try (BufferedWriter outFP = new BufferedWriter(new FileWriter(fileName))) {
            outFP.write("// " + comment + "\n\n");
            outFP.write(outputProgram(knownPeers));
        }
    }
}
