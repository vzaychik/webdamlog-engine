$:.unshift File.dirname(__FILE__)
require '../header_test'
require_relative '../../lib/webdamlog_runner'

require 'test/unit'

# this test case is to check following: (where a is ext and b is int)
# If we have three relations
#a@peer($x) :- c@peer($x)
#b@peer($x) :- c@peer($x)
# if we delete a fact from 'c', it should be deleted from 'b' as well but not from 'a'
# This is for option - with access control ON

class TcAccessRemovePriviledgeAdv < Test::Unit::TestCase
    include MixinTcWlTest
    
    
    #setting up the rules inside a file
    def setup
        @pg1 = <<-EOF
        peer p1=localhost:11115;
        peer p2=localhost:11116;
        collection int rel1_i@p1(atom1*);
        fact rel1_i@p1(3);
        fact rel1_i@p1(5);
        rule rel2@p2($x) :- rel1_i@p1($x); # these are the rules which are the basis for this test
        rule rel3_i@p2($x) :- rel1_i@p1($x); # rel2 is ext, rel 1 and rel3 are intentional, infact relation 3 is a direct copy(view) of relation 1
    end
    EOF
    @username1 = "p1"
    @port1 = "11115"
    @pg_file1 = "New_delete_fact_test"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
    
    @pg2 = <<-EOF
    peer p1=localhost:11115;
    peer p=localhost:11116;
    collection ext per rel2@p2(atom1*);
    collection int rel3_i@p2(atom1*);
    end
    EOF
    @username2 = "p2"
    @port2 = "11116"
    @pg_file2 = "New2_delete_fact_test"
    File.open(@pg_file2,"w"){ |file| file.write @pg2 }
    end


    def teardown
        ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
        ObjectSpace.garbage_collect
    end

def test_remove_priviledge_adv
        runner1 = nil
        runner2 = nil
        assert_nothing_raised do
            runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true })
            runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true })
    end
        
        runner2.tick
        runner1.tick
        
        assert_equal [{:atom1=>"3"}, {:atom1=>"5"}], runner1.tables[:rel1_i_at_p1].map{ |t| Hash[t.each_pair.to_a]}
        #assert_equal [], runner2.tables[:rel2_i_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
        
        
        # updating the priviledge at peer p2 for collection defined on peer p1
        
        ##p1 gives read access to rel2 at p2 and rel 2 at p2 gives write access to p1
        
        runner1.update_acl("rel1_i_at_p1","p2","R")
        runner2.update_acl("rel2_at_p2","p1","W")
        
        # rel3 on p2 gives write access to p1
        runner2.update_acl("rel3_i_at_p2","p1","W")
        
        runner2.tick
        runner2.tick
        runner1.tick
        runner1.tick
 
        #checking that data is materialized # { Always check if the relation is intentionsal or extensional, for extentional the peer set should be different (omega-ish)
        assert_equal [{:priv=>"R", :atom1=>"3", :plist=>Omega.instance},{:priv=>"R", :atom1=>"5", :plist=>Omega.instance}, {:priv=>"G", :atom1=>"3", :plist=>Omega.instance},{:priv=>"G", :atom1=>"5", :plist=>Omega.instance}],runner2.tables[:rel2_plus_at_p2].map{ |t| Hash[t.each_pair.to_a]}

#checking that data is materialized for intentional relation rel3_i_at_p2 ( always check at extended relation)
assert_equal [{:priv=>"R", :atom1=>"3", :plist=>PList.new(["p1", "p2"].to_set)}, {:priv=>"R", :atom1=>"5", :plist=>PList.new(["p1", "p2"].to_set)}],runner2.tables[:rel3_i_plus_at_p2].map{ |t| Hash[t.each_pair.to_a]}


        #delete the facts from relation 1
        runner1.delete_facts({"rel1_i_at_p1"=>[["3"]]})
        runner1.delete_facts({"rel1_i_at_p1"=>[["5"]]})

        # running the peers
        runner2.tick
        runner1.tick
        runner2.tick
        runner1.tick
        runner2.tick
        runner1.tick
        
        #verify relation 1 contents at p1
        assert_equal [],runner1.snapshot_facts(:rel1_i_at_p1)
        
        # verify ext rel 1 contents at p1
        assert_equal [],runner1.snapshot_facts(:rel1_i_plus_at_p1)
        
        # after removing the facts, nothing should be available in rel3 as it is a view and should have been deleted with deletion of facts from relation 1 above
        assert_equal [], runner2.tables[:rel3_i_plus_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
        # rel2 should be same as it is an extentional relation and there is no effect on the data inside relation 2 with deletion of facts in relation 1
        assert_equal [{:priv=>"R", :atom1=>"3", :plist=>Omega.instance}, {:priv=>"R", :atom1=>"5", :plist=>Omega.instance}],runner2.tables[:rel2_plus_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
        
        ensure
        File.delete(@pg_file1) if File.exists?(@pg_file1)
        File.delete(@pg_file2) if File.exists?(@pg_file2)
        if EventMachine::reactor_running?
            runner1.stop
            runner2.stop
        end
         
    end
    
end
