$:.unshift File.dirname(__FILE__)
require 'header_test'
require_relative '../lib/webdamlog_runner'

require 'test/unit'

# this test case is to check what happens if a priviledge is revoked from the relation
# Expected - If a permission is revoked, the data should not be materialized

class TcAccessRemovePriviledge < Test::Unit::TestCase
    include MixinTcWlTest
    
    def setup
        @pg1 = <<-EOF
        peer p1=localhost:11115;
        peer p2=localhost:11116;
        collection int rel1_i@p1(atom1*);
        fact rel1_i@p1(3);
        fact rel1_i@p1(5);
        rule rel2_i@p2($x) :- rel1_i@p1($x);
    end
    EOF
    @username1 = "p1"
    @port1 = "11115"
    @pg_file1 = "New_remove_priviledge_test"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
    
    @pg2 = <<-EOF
    peer p1=localhost:11115;
    peer p=localhost:11116;
    collection int rel2_i@p2(atom1*);
    end
    EOF
    @username2 = "p2"
    @port2 = "11116"
    @pg_file2 = "New2_remove_priviledge_test"
    File.open(@pg_file2,"w"){ |file| file.write @pg2 }
    end

    def teardown
        ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
        ObjectSpace.garbage_collect
    end

def test_remove_priviledge
        runner1 = nil
        runner2 = nil
        assert_nothing_raised do
            runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true })
            runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true })
    end
        
        runner2.tick
        runner1.tick
        
        assert_equal [{:atom1=>"3"}, {:atom1=>"5"}], runner1.tables[:rel1_i_at_p1].map{ |t| Hash[t.each_pair.to_a]}
        assert_equal [], runner2.tables[:rel2_i_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
        
        
        # updating the priviledge at peer p2 for collection defined on peer p1
        
        runner1.update_acl("rel1_i_at_p1","p2","R")
        runner2.update_acl("rel2_i_at_p2","p1","W")
        
        runner2.tick
        runner2.tick
        runner1.tick
        runner1.tick
 
        #checking that data is materialized
assert_equal [{:priv=>"R", :atom1=>"3", :plist=>PList.new(["p1", "p2"].to_set)}, {:priv=>"R", :atom1=>"5", :plist=>PList.new(["p1", "p2"].to_set)}],runner2.tables[:rel2_i_plus_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
        
        #removing the fact
        runner1.delete_acl("rel1_i_at_p1","p2","R")


        # running the peers
        runner2.tick
        runner1.tick
        runner2.tick
        runner1.tick
        runner2.tick
        runner1.tick
        
        #verify acl contents
        assert_equal [],runner1.snapshot_facts(:acl_at_p1)
        
        # after removing the facts, nothing should be materialized
        assert_equal [], runner2.tables[:rel2_i_plus_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
        
        
        ensure
        File.delete(@pg_file1) if File.exists?(@pg_file1)
        File.delete(@pg_file2) if File.exists?(@pg_file2)
        if EventMachine::reactor_running?
            runner1.stop
            runner2.stop
        end
         
    end
    
end
