package org.webdam.datagen;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
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
    private ArrayList<Collec> _collections;
    private HashMap<String, Collec> _slave_coll;

    public Peer(int id, PEER_TYPE type) {
        _id = id;
        _auxId = id;
        _type = type;
        _slaves = new ArrayList<>();
        _masters = new ArrayList<>();
        _knownPeers = new HashSet<>();
        _collections = new ArrayList<>();
        _slave_coll = new HashMap<>();
    }

    public Peer(int id, PEER_TYPE type, SCENARIO scenario) {
        _id = id;
        _auxId = id;
        _type = type;
        _slaves = new ArrayList<>();
        _masters = new ArrayList<>();
        _knownPeers = new HashSet<>();
        _collections = new ArrayList<>();
        _slave_coll = new HashMap<>();
        _scenario = scenario;        
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
        if (AggregatorsFollowers._netAddressMap.containsKey(_id)) {
            host = AggregatorsFollowers._netAddressMap.get(_id);
        }
        return host + ":" + (Constants.PORT_OFFSET + _id);
    }

    public ArrayList<Collec> getCollections() {
        return _collections;
    }

    public Collec getCollectionByName(String name) {
        for (Collec c : _collections) {
            if (c.getName().equalsIgnoreCase(name)) {
                return c;
            }
        }
        return null;
    }

    public ArrayList<Peer> getSlaves() {
        return _slaves;
    }

    public Collection<Collec> getSlaveColls() {
        return _slave_coll.values();
    }

    public void addMaster(Peer p) {
        _masters.add(p);
        _knownPeers.add(p);
    }

    /**
     * Add the slave p to this peer.
     *
     * A slave is a peer that will send facts to a local relation in this peer.
     *
     * @param p
     */
    public void addSlave(Peer p) {
        _slaves.add(p);
        _knownPeers.add(p);
        if (_type.equals(PEER_TYPE.AGGREGATOR)) {
            Collec slave_rel = new Collec("a_hasslave_" + p.getId(), this.getName(), COL_TYPE.INT, 0, "x");
            _collections.add(slave_rel);
            _slave_coll.put(slave_rel.getName(), slave_rel);
        } else if (_type.equals(PEER_TYPE.MASTER)) {
            Collec slave_rel = new Collec("m_hasslave_" + p.getId(), this.getName(), COL_TYPE.INT, 0, "x");
            _collections.add(slave_rel);
            _slave_coll.put(slave_rel.getName(), slave_rel);
        }
    }

    public void addSlave(Peer p, String nonKeys) {
        _slaves.add(p);
        _knownPeers.add(p);
        if (_type.equals(PEER_TYPE.AGGREGATOR)) {
            _collections.add(new Collec("a_hasslave_" + p.getId(), this.getName(), COL_TYPE.INT, 0, "x", nonKeys));
        } else if (_type.equals(PEER_TYPE.MASTER)) {
            _collections.add(new Collec("m_hasslave_" + p.getId(), this.getName(), COL_TYPE.INT, 0, "x", nonKeys));
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
    public void addCollection(Collec c) {
        _collections.add(c);
    }

    public void setPolicy(POLICY policy) {
        _policy = policy;
    }

    public void setScenario(SCENARIO scenario) {
        _scenario = scenario;
    }

    public SCENARIO getScenario() {
        return _scenario;
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
        for (Collec c : _collections) {
            prog.append("collection ").append(c.getType().toString()).append(c.isPersistentToString()).append(c.getSchema()).append(";\n");
        }
        return prog.toString();
    }

    public String outputFacts() {
        StringBuilder prog = new StringBuilder("// facts\n");
        for (Collec c : _collections) {
            for (String fact : c.getFacts()) {
                prog.append("fact ").append(c.getName()).append(c.getSuffix()).append("@").append(this.getName()).append("(").append(fact).append(");\n");
            }
        }
        return prog.toString();
    }

    public String outputPolicy() {
        StringBuilder prog = new StringBuilder("// access control policy\n");
        if (_policy == POLICY.PUB) {
            for (Collec c : _collections) {
                prog.append("policy ").append(c.getName()).append(c.getSuffix()).append(" read ALL;\n");
                prog.append("policy ").append(c.getName()).append(c.getSuffix()).append(" write ALL;\n");
            }
        } else if (_policy == POLICY.KNOWN) {
            for (Collec c : _collections) {
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
                    Collec headC = m.getCollectionByName("m");
                    Collec bodyC = this.getCollectionByName("f");
                    prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyC.getSchemaWithVars()).append(";\n");
                }

                // take the join of r@follower_i(x*), store result in s@aggregator(x*)
                Collec headC = this.getCollectionByName("f");
                String bodyOfJoinRule = "";
                for (Peer f : _slaves) {
                    Collec bodyC = f.getCollectionByName("a");
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
                Collec headC = this.getCollectionByName("m");
                String bodyOfJoinRule = "";
                for (Peer f : _slaves) {
                    Collec bodyC = f.getCollectionByName("f");
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
                    Collec headC = m.getCollectionByName("f");
                    Collec bodyC = this.getCollectionByName("a");
                    prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyC.getSchemaWithVars()).append(";\n");
                }
            }
            
        } else if (_scenario == SCENARIO.ALBUM) {

            if (_type == PEER_TYPE.SUE) {
                Peer alice = Album._peersList.get(0);
                Peer bob = Album._peersList.get(1);

                // compute a union of friends@alice and friends@bob, store in all_friends@sue
                Collec allFriends = this.getCollectionByName("all_friends");
                Collec friendsAlice = alice.getCollectionByName("friends");
                Collec friendsBob = bob.getCollectionByName("friends");
                prog.append("rule ").append(allFriends.getSchemaWithVars()).append(" :- ").append(friendsAlice.getSchemaWithVars()).append(";\n");
                prog.append("rule ").append(allFriends.getSchemaWithVars()).append(" :- ").append(friendsBob.getSchemaWithVars()).append(";\n");

                // compute the contents of album@sue($img,$peer)
                Collec album = this.getCollectionByName("album");
                prog.append("rule ").append(album.getSchemaWithVars()).append(" :- ").append(allFriends.getSchemaWithVars()).append(", photos@$peer($img), tags@$peer($img,\"").append(alice.getName()).append("\"), tags@$peer($img,\"").append(bob.getName()).append("\");\n");
            }

        } else if (_scenario == SCENARIO.AGGFOLUNION) {

            if (_type == PEER_TYPE.MASTER) {
                // no rules
            } else if (_type == PEER_TYPE.AGGREGATOR) {

                // send the contents of relation a@thispeer(x) to relation m@master(x), on each master
                for (Peer m : _masters) {
                    Collec headC = m.getCollectionByName("m");
                    Collec bodyC = this.getCollectionByName("a");
                    prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyC.getSchemaWithVars()).append(";\n");
                }

                // take the join of f@follower_i(x*), store result in a@aggregator(x*)
                Collec headC = this.getCollectionByName("a");
                String bodyOfJoinRule = "";
                for (Peer f : _slaves) {
                    Collec bodyC = f.getCollectionByName("f");
                    if (bodyOfJoinRule.length() > 0) {
                        bodyOfJoinRule += ", ";
                    }
                    bodyOfJoinRule += bodyC.getSchemaWithVars();
                }
                prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyOfJoinRule).append(";\n");

            } else if (_type == PEER_TYPE.FOLLOWER) {
                // TODO
                for (int i=0; i<Constants.REL_IN_JOINS; i++) {
                    
                }
                for (Peer m : _masters) {
                    Collec headC = m.getCollectionByName("m");
                    Collec bodyC = this.getCollectionByName("a");
                    prog.append("rule ").append(headC.getSchemaWithVars()).append(" :- ").append(bodyC.getSchemaWithVars()).append(";\n");
                }
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
