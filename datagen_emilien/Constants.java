package org.webdam.datagen;

public class Constants {

    public static enum PEER_TYPE {

        FOLLOWER, AGGREGATOR, MASTER, ALICE, BOB, SUE, PEER
    };

    public static enum COL_TYPE {

        INT, EXT
    };

    /**
     *
     * <ul>
     * <li> public policy says that all peers see all data
     * <li> private policy says that only the local peer can read its data
     * <li> KNOWN policy says that the local peer and all peers that it knows
     * about(its masters and slaves) can read its data
     * <ul>
     */
    public static enum POLICY {

        PUB, PRIV, KNOWN
    }
    // the range of values for the facts in the relations
    // public static int VAL_RANGE = 100;
    // offset for port numbering
    public static int PORT_OFFSET = 10000;

    // In the UNION_OF_JOINS scenario, master takes a union of the aggregators, while aggregators take a join of the followers.
    // In the JOIN_OF_UNIONS scenario, master takes a join of the aggregators, while aggregators take a union of the followers.
    public static enum SCENARIO {

        UNION_OF_JOINS, JOIN_OF_UNIONS, ALBUM, AGGFOLUNION
    }
    /**
     * Set to true to write all the rule in the master node.
     *
     * Rules could be added to any peers objects. If MASTER_ONLY_RULES if false
     * the rules will be written in the program of each peer. If
     * MASTER_ONLY_RULES is true, the location of the rule is ignored and all
     * the rule will be written in the program of master.
     * <p>
     * Used to be sure that except master no peer will start processing.
     */
    public static boolean MASTER_ONLY_RULES = true;
    
    /**
     * Set to true to create the program files.
     *
     * Usually let it to true, false maybe used for test purpose only.
     */
    public static boolean DO_FILE_IO = true;

    
    // Album constants
    public static float PROB_ALICE_OR_BOB_IN_PHOTO = 0.5f;
    public static float PROB_OTHER_PEER_IN_PHOTO = 0.1f;
    // the length of the extra columns in the MAF scenario
    public static String EXTRA_COL = "\"ABCDEFGHIJ\"";

    //AggFolUnion constants

    /**
     * Set the number of relations to join in the followers
     */
    public static int REL_IN_JOINS = 3;
    
}
