package org.stoyanovich.webdam.datagen;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;

import org.stoyanovich.webdam.datagen.Constants.COL_TYPE;

/**
 * An implementation of a collection, for the purpose of data generation.
 * @author Julia Stoyanovich
 *
 */
public class Collection {
	public String _name;
	public String _suffix;
	public String _peerName;
	public String _schema;
	public String _schemaWithVars;
	public COL_TYPE _type;
	public ArrayList<String> _keys;
	public ArrayList<String> _nonKeys;
	public int _isPersistent = 0;
	public HashSet<String> _facts;

	public Collection(String name, String peerName, COL_TYPE type, int isPersistent, String keys, String nonKeys) {
		_name = name;
		_peerName = peerName;
		_type = type;
		if (_type.equals(COL_TYPE.EXT)) {
			_isPersistent = isPersistent;
			_suffix="";
		} else {
			_isPersistent = 0;
			_suffix="_i";
		}
		_keys = new ArrayList<String>();
		_nonKeys = new ArrayList<String>();
		_facts = new HashSet<String>();
		
		String[] tmp = keys.trim().split(",");
		for (int i=0; i<tmp.length; i++) {
			_keys.add(tmp[i]);
		}
		
		if (nonKeys.length() > 0) {
			tmp = nonKeys.trim().split(",");
			_nonKeys = new ArrayList<String>();
			for (int i=0; i<tmp.length; i++) {
				_nonKeys.add(tmp[i]);
			}
		}
	
		_schema = _name + _suffix + "@" + peerName + "(" + keysToString() + nonKeysToString()  + ")";
		_schemaWithVars = _name + _suffix + "@" + peerName + "(" + colsToString() + ")";
		
	}
	
	public Collection(String name, String peerName, COL_TYPE type, int isPersistent, String keys) {
		this (name, peerName, type, isPersistent, keys, "");
	}

	public Collection(String name, String peerName, COL_TYPE type, int isPersistent, String keys,int numFacts, int valRange) {
		this (name, peerName, type, isPersistent, keys);
		this.addFacts(numFacts, valRange);
	}

	public String getType() {
		return _type.toString().toLowerCase();
	}
	
	public String isPersistentToString() {
		return (_isPersistent == 1) ? " per " : " ";
	}
	
	public String getName() {
		return _name;
	}

	public String getSuffix() {
		return _suffix;
	}
	public String getSchema() {
		return _schema;
	}
	
	public String getSchemaWithVars() {
		return _schemaWithVars;
	}

	public int getNumFacts() {
		return _facts.size();
	}
	
	public HashSet<String> getFacts() {
		return _facts;
	}
	
	public String keysToString() {
		StringBuffer res = new StringBuffer();
		for (String key : _keys) {
			if (res.length() > 0) {
				res.append(",");
			}
			res.append(key + "*");
		}
		return res.toString();
	}
	
	public String nonKeysToString() {
		StringBuffer res = new StringBuffer();
		for (String key : _nonKeys) {
			res.append(key);
		}
		return res.toString();
	}

	public String colsToString() {
		StringBuffer res = new StringBuffer();
		for (String key : _keys) {
			if (res.length() > 0) {
				res.append(",");
			}
			res.append("$" + key);
		}		
		for (String key : _nonKeys) {
			res.append(",$" + key);
		}
		return res.toString();
	}

	/**
	 * It's only allowed to explicitly add facts to extensional collections.
	 * We are adding a give number of facts, that are simply random numbers between 0 and range-1.
	 */
	public void addFacts(int numFacts, int valRange) {
		if (_type == COL_TYPE.EXT) {
			Random rand = new Random();
			for (int i=0; i<numFacts; i++) {
				_facts.add("" + rand.nextInt(valRange));
			}
		}
	}
	
	public void addFact(String fact) {
		_facts.add(fact);
	}
	
}
