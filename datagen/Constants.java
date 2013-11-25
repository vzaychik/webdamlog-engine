package org.stoyanovich.webdam.datagen;

/**
 * Constants.
 * @author Julia Stoyanovich
 *
 */
public class Constants {

	public static enum PEER_TYPE {FOLLOWER, AGGREGATOR, MASTER, ALICE, BOB, SUE, PEER};
	public static enum COL_TYPE {INT, EXT};
	
	// public policy says that all peers see all data
	// private policy says that only the local peer can read its data
	// KNOWN policy says that the local peer and all peers that it knows about (its masters and slaves) can read its data
	public static enum POLICY {PUB, PRIV, KNOWN}
	
	// the range of values for the facts in the relations
	public static int VAL_RANGE = 10000;
	
	// offset for port numbering
	public static int PORT_OFFSET = 10000;
	
	// In the UNION_OF_JOINS scenario, master takes a union of the aggregators, while aggregators take a join of the followers.
	// In the JOIN_OF_UNIONS scenario, master takes a join of the aggregators, while aggregators take a union of the followers.
	public static enum SCENARIO {UNION_OF_JOINS, JOIN_OF_UNIONS, ALBUM}
	
	public static boolean MASTER_ONLY_RULES = true;
	
	public static boolean DO_FILE_IO = true;
	
	public static float PROB_ALICE_OR_BOB_IN_PHOTO = 0.5f;
	public static float PROB_OTHER_PEER_IN_PHOTO = 0.1f;

}
