package org.stoyanovich.webdam.datagen;

//Adapted from http://algs4.cs.princeton.edu/42directed/TransitiveClosure.java
/*************************************************************************
 *  Compute transitive closure of a digraph and support
 *  reachability queries.
 *
 *  Preprocessing time: O(V(E + V)) time.
 *  Query time: O(1).
 *  Space: O(V^2).
 *
 *************************************************************************/

/**
 *  The <tt>TransitiveClosure</tt> class represents a data type for 
 *  computing the transitive closure of a digraph.
 *  <p>
 *  This implementation runs depth-first search from each vertex.
 *  The constructor takes time proportional to <em>V</em>(<em>V</em> + <em>E</em>)
 *  (in the worst case) and uses space proportional to <em>V</em><sup>2</sup>,
 *  where <em>V</em> is the number of vertices and <em>E</em> is the number of edges.
 *  <p>
 *  For additional documentation, see <a href="/algs4/42digraph">Section 4.2</a> of
 *  <i>Algorithms, 4th Edition</i> by Robert Sedgewick and Kevin Wayne.
 *
 *  @author Robert Sedgewick
 *  @author Kevin Wayne
 */
public class TransitiveClosure {
    private DirectedDFS[] tc;  // tc[v] = reachable from v

    /**
     * Computes the transitive closure of the digraph <tt>G</tt>.
     * @param G the digraph
     */
    public TransitiveClosure(Digraph G) {
        tc = new DirectedDFS[G.V()];
        for (int v = 0; v < G.V(); v++)
            tc[v] = new DirectedDFS(G, v);
    }

    /**
     * Is there a directed path from vertex <tt>v</tt> to vertex <tt>w</tt> in the digraph?
     * @param v the source vertex
     * @param w the target vertex
     * @return <tt>true</tt> if there is a directed path from <tt>v</tt> to <tt>w</tt>,
     *    <tt>false</tt> otherwise
     */
    public boolean reachable(int v, int w) {
        return tc[v].marked(w);
    }

    public int sizeFrom(int v) {
	return tc[v].count();
    }

    public DirectedDFS getDFS(int v) {
	return tc[v];
    }

}