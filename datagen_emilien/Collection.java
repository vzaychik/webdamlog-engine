package org.webdam.datagen;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import org.webdam.datagen.Constants.COL_TYPE;

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
            _suffix = "";
        } else {
            _isPersistent = 0;
            _suffix = "_i";
        }
        _keys = new ArrayList<>();
        _nonKeys = new ArrayList<>();
        _facts = new HashSet<>();

        String[] tmp = keys.trim().split(",");
        _keys.addAll(Arrays.asList(tmp));

        if (nonKeys.length() > 0) {
            tmp = nonKeys.trim().split(",");
            _nonKeys = new ArrayList<>();
            _nonKeys.addAll(Arrays.asList(tmp));
        }
        
        _schema = _name + _suffix + "@" + peerName + "(" + keysToString() + nonKeysToString() + ")";
        _schemaWithVars = _name + _suffix + "@" + peerName + "(" + colsToString() + ")";
    }

    public Collection(String name, String peerName, COL_TYPE type, int isPersistent, String keys) {
        this(name, peerName, type, isPersistent, keys, "");
    }

    public Collection(String name, String peerName, COL_TYPE type, int isPersistent, String keys, int numFacts, int valRange) {
        this(name, peerName, type, isPersistent, keys);
        this.addFacts(numFacts, valRange);
    }

    public Collection(String name, String peerName, COL_TYPE type, int isPersistent, String keys, String nonKeys, int numFacts, int valRange) {
        this(name, peerName, type, isPersistent, keys, nonKeys);
        this.addFacts(numFacts, valRange, this._nonKeys.size());
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

    private String keysToString() {
        StringBuilder res = new StringBuilder();
        for (String key : _keys) {
            if (res.length() > 0) {
                res.append(",");
            }
            res.append(key).append("*");
        }
        return res.toString();
    }

    private String nonKeysToString() {
        StringBuilder res = new StringBuilder();
        for (String str : _nonKeys) {
            res.append(",").append(str);
        }
        return res.toString();
    }

    private String colsToString() {
        StringBuilder res = new StringBuilder();
        for (String key : _keys) {
            if (res.length() > 0) {
                res.append(",");
            }
            res.append("$").append(key);
        }
        for (String key : _nonKeys) {
            res.append(",$").append(key);
        }
        return res.toString();
    }

    /**
     * It's only allowed to explicitly add facts to extensional collections. We
     * are adding a give number of facts, that are simply random numbers between
     * 0 and range-1.
     */
    private void addFacts(int numFacts, int valRange) {
        if (_type == COL_TYPE.EXT) {
            Random rand = new Random();
            for (int i = 0; i < numFacts; i++) {
                _facts.add("" + rand.nextInt(valRange));
            }
        }
    }

    /**
     * Generate facts that have a key column and the specified number of extra
     * columns
     *
     * @param numFacts
     * @param valRange
     * @param numExtraCols
     */
    private void addFacts(int numFacts, int valRange, int numExtraCols) {
        if (_type == COL_TYPE.EXT) {
            Random rand = new Random();
            for (int i = 0; i < numFacts; i++) {
                StringBuilder fact = new StringBuilder("" + rand.nextInt(valRange));
                for (int col = 0; col < numExtraCols; col++) {
                    fact.append(",").append(Constants.EXTRA_COL);
                }
                _facts.add(fact.toString());
            }
        }
    }

    public void addFact(String fact) {
        _facts.add(fact);
    }
}
