$:.unshift File.dirname(__FILE__)
require_relative '../header_test'
require_relative '../../lib/webdamlog_runner'

require 'test/unit'

#Test collections get additional attributes, facts get default permissions set from acl relation
class TcAccessGrammar < Test::Unit::TestCase
    include MixinTcWlTest
    
    def setup
        @pg = <<-EOF
        peer p1=localhost:11111;
        peer test_access=localhost:11110;
        collection ext per local2@test_access(atom1*);
        collection ext per local1@test_access(atom1*);
        collection int local3_i@test_access(atom1*);
        fact local2@test_access(1);
        fact local2@test_access(2);
        policy local2 read ALL;
        policy local1 read p1;
        policy local3_i write p1;
        rule local1@test_access($x) :- [PRESERVE local2@test_access($x)];
        rule local3_i@test_access($x) :- [HIDE local2@test_access($x)];
    end
    EOF
    @username = "test_access"
    @port = "11110"
    @pg_file = "test_access_control_grammar"
    File.open(@pg_file,"w"){ |file| file.write @pg }
end

def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
end

# check that facts have psets correctly set
def test_access_grammar
    begin
        runner = nil
        assert_nothing_raised do
            runner = WLRunner.create(@username, @pg_file, @port, {:accessc => true, :debug => true, :noprovenance => true })
        end
        
        assert_equal({1=> "rule local1@test_access($x) :- [PRESERVE local2@test_access($x)];", 2=> "rule local3_i@test_access($x) :- [HIDE local2@test_access($x)];"}, runner.snapshot_rules)
        
        assert_equal [{:atom1=>"1", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"G", :plist=>Omega.instance}], runner.tables[:local2_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a]}
        
        
        assert_equal [{:atom1=>"1", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>PList.new(["test_access"].to_set)}, {:atom1=>"2", :priv=>"G", :plist=>PList.new(["test_access"].to_set)}], runner.tables[:local1_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a]}
        assert_equal [{:atom1=>"1", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"G", :plist=>Omega.instance}], runner.tables[:local3_i_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a]}
        
        assert_equal(["policy local2 read ALL","policy local1 read p1","policy local3_i write p1"], runner.snapshot_policies)
        
        ensure
        runner.stop
        File.delete(@pg_file) if File.exists?(@pg_file)
    end
end
end


class TcAccessAdvancedRules < Test::Unit::TestCase
    include MixinTcWlTest
    
    def setup
        @pg1 = <<-EOF
        peer p1=localhost:11112;
        peer p2=localhost:11113;
        peer p=localhost:11114;
        collection int r_i@p(atom1*);
        collection int r2_i@p(atom1*);
        rule r_i@p($x) :- s@p1($x), s@p2($x);
        rule r2_i@p($x) :- s@p1($x);
        rule r2_i@p($x) :- s@p2($x);
    end
    EOF
    @username1 = "p"
    @port1 = "11114"
    @pg_file1 = "p_advanced_test"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
    
    @pg2 = <<-EOF
    peer p1=localhost:11112;
    peer p2=localhost:11113;
    peer p=localhost:11114;
    collection ext per s@p1(atom1*);
    fact s@p1(3);
    fact s@p1(4);
end
EOF
@username2 = "p1"
@port2 = "11112"
@pg_file2 = "p1_advanced_test"
File.open(@pg_file2,"w"){ |file| file.write @pg2 }

@pg3 = <<-EOF
peer p1=localhost:11112;
peer p2=localhost:11113;
peer p=localhost:11114;
collection ext per s@p2(atom1*);
fact s@p2(5);
fact s@p2(6);
end
EOF
@username3 = "p2"
@port3 = "11113"
@pg_file3 = "p2_advanced_test"
File.open(@pg_file3,"w"){ |file| file.write @pg3 }
end

def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
end

def test_remote_rules
    begin
        runner1 = nil
        runner2 = nil
        runner3 = nil
        assert_nothing_raised do
            runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true })
            runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true })
            runner3 = WLRunner.create(@username3, @pg_file3, @port3, {:accessc => true, :debug => true })
        end
        
        
        runner2.tick
        runner3.tick
        runner1.tick
        
        runner2.update_acl("s_at_p1","p","R")
        runner3.update_acl("s_at_p2","p","R")
        runner1.update_acl("r2_i_at_p","p2","W");
        runner1.update_acl("r2_i_at_p","p1","W");
        
        assert_equal [{:atom1=>"5", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"5", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"6", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"6", :priv=>"G", :plist=>Omega.instance}], runner3.tables[:s_plus_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
        runner2.tick
        runner3.tick
        runner2.tick
        runner3.tick
        runner2.tick
        runner3.tick
        runner2.tick
        runner3.tick
        runner1.tick
        
        assert_equal [{:atom1=>"5", :priv=>"R", :plist=>PList.new(["p", "p2"].to_set)},{:atom1=>"6", :priv=>"R", :plist=>PList.new(["p", "p2"].to_set)},{:atom1=>"3", :priv=>"R", :plist=>PList.new(["p", "p1"].to_set)},{:atom1=>"4", :priv=>"R", :plist=>PList.new(["p", "p1"].to_set)}], runner1.tables[:r2_i_plus_at_p].map{ |t| Hash[t.each_pair.to_a]}
        assert_equal [], runner1.tables[:r_i_plus_at_p].map{ |t| Hash[t.each_pair.to_a]}
        
        ensure
        File.delete(@pg_file1) if File.exists?(@pg_file1)
        File.delete(@pg_file2) if File.exists?(@pg_file2)
        File.delete(@pg_file3) if File.exists?(@pg_file3)
        if EventMachine::reactor_running?
            runner1.stop
            runner2.stop
            runner3.stop
        end
    end
    
end
end


class TcAccessDelegProven < Test::Unit::TestCase
    include MixinTcWlTest
    
    def setup
        @pg1 = <<-EOF
        peer p1=localhost:11115;
        peer p=localhost:11116;
        collection int r_i@p(atom1*);
        collection int r2_i@p(atom1*);
        collection ext per local@p(atom1*);
        collection int r3_i@p(atom1*);
        fact local@p(3);
        fact local@p(5);
        rule r_i@p($x) :- [HIDE s@p1($x)];
        rule r2_i@p($x) :- s@p1($x);
        rule r3_i@p($x) :- local@p($x),[HIDE s@p1($x)];
    end
    EOF
    @username1 = "p"
    @port1 = "11116"
    @pg_file1 = "p_advanced_test"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
    
    @pg2 = <<-EOF
    peer p1=localhost:11115;
    peer p=localhost:11116;
    collection ext per s@p1(atom1*);
    fact s@p1(3);
    fact s@p1(4);
end
EOF
@username2 = "p1"
@port2 = "11115"
@pg_file2 = "p1_advanced_test"
File.open(@pg_file2,"w"){ |file| file.write @pg2 }

end

def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
end

def test_deleg_proven
    begin
        runner1 = nil
        runner2 = nil
        assert_nothing_raised do
            runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true })
            runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true })
        end
        
        
        runner2.tick
        runner1.tick
        
        runner1.update_acl("local_at_p","p1","R")
        runner2.update_acl("s_at_p1","p","R")
        runner2.update_acl("s_at_p1","p2","R")
        runner1.update_acl("r_i_at_p","p1","W")
        runner1.update_acl("r2_i_at_p","p1","W")
        runner1.update_acl("r3_i_at_p","p1","W")
        
        runner2.tick
        runner2.tick
        runner1.tick
        runner2.tick
        runner1.tick
        runner2.tick
        runner1.tick
        runner2.tick
        runner1.tick
        
        assert_equal [{:atom1=>"3", :priv=>"R", :plist=>PList.new(["p", "p1", "p2"].to_set)},{:atom1=>"4", :priv=>"R", :plist=>PList.new(["p", "p1", "p2"].to_set)}], runner1.tables[:r2_i_plus_at_p].map{ |t| Hash[t.each_pair.to_a]}
        #without grant priv nothing would materialize
        assert_equal [], runner1.tables[:r_i_plus_at_p].map{ |t| Hash[t.each_pair.to_a]}
        
        runner2.update_acl("s_at_p1","p","G")
        runner2.tick
        runner1.tick
        
        assert_equal [{:atom1=>"3", :priv=>"R", :plist=>Omega.instance},{:atom1=>"4",:priv=>"R",:plist=>Omega.instance}, {:atom1=>"3", :priv=>"G", :plist=>Omega.instance},{:atom1=>"4",:priv=>"G",:plist=>Omega.instance}], runner1.tables[:r_i_plus_at_p].map{ |t| Hash[t.each_pair.to_a]}
        
        assert_equal [{:atom1=>"3", :priv=>"R", :plist=>PList.new(["p","p1"].to_set)}], runner1.tables[:r3_i_plus_at_p].map{ |t| Hash[t.each_pair.to_a]}
        
        ensure
        File.delete(@pg_file1) if File.exists?(@pg_file1)
        File.delete(@pg_file2) if File.exists?(@pg_file2)
        if EventMachine::reactor_running?
            runner1.stop
            runner2.stop
        end
    end
    
end
end

class TcAccessDuplicates < Test::Unit::TestCase
    include MixinTcWlTest
    
    def setup
        @pg = <<-EOF
        peer p1=localhost:11111;
        peer test_access=localhost:11110;
        collection int local1_i@test_access(atom1*);
        collection ext per local2@test_access(atom1*);
        collection ext per local3@test_access(atom1*);
        fact local2@test_access(1);
        fact local2@test_access(2);
        fact local3@test_access(2);
        fact local3@test_access(3);
        rule local1_i@test_access($x) :- local2@test_access($x);
        rule local1_i@test_access($x) :- local3@test_access($x);
    end
    EOF
    @username = "test_access"
    @port = "11110"
    @pg_file = "test_access_control_duplicates"
    File.open(@pg_file,"w"){ |file| file.write @pg }
end

def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
end

def test_duplicates
    begin
        runner = nil
        assert_nothing_raised do
            runner = WLRunner.create(@username, @pg_file, @port, {:accessc => true, :debug => true })
        end
        
        runner.update_acl("local2_at_test_access","p1","R")
        runner.update_acl("local3_at_test_access","p2","R");
        
        runner.tick
        runner.tick
        
        assert_equal [{:atom1=>"1", :priv=>"G", :plist=>PList.new(["test_access"].to_set)}, {:atom1=>"2", :priv=>"G", :plist=>PList.new(["test_access"].to_set)}, {:atom1=>"1", :priv=>"R", :plist=>PList.new(["test_access","p1"].to_set)}, {:atom1=>"2", :priv=>"R", :plist=>PList.new(["test_access","p1","p2"].to_set)}, {:atom1=>"3", :priv=>"G", :plist=>PList.new(["test_access"].to_set)}, {:atom1=>"3", :priv=>"R", :plist=>PList.new(["test_access","p2"].to_set)}], runner.snapshot_facts(:local1_i_plus_at_test_access)
        
        ensure
        runner.stop
        File.delete(@pg_file) if File.exists?(@pg_file)
    end
    
end
end
