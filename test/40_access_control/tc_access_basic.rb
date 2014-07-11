$:.unshift File.dirname(__FILE__)
require '../header_test'
require_relative '../../lib/webdamlog_runner'

require 'test/unit'

#Test collections get additional attributes, facts get default permissions set from acl relation
class TcAccessBasic < Test::Unit::TestCase
  include MixinTcWlTest
  
  def setup
    @pg = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local1@test_access(atom1*);
collection ext per local2@test_access(atom1*, atom2);
fact local1@test_access(1);
fact local1@test_access(2);
end
    EOF
    @username = "test_access"
    @port = "11110"
    @pg_file = "test_access_control_basic_program"
    File.open(@pg_file,"w"){ |file| file.write @pg }
  end

  def teardown    
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  # check that facts have psets correctly set
  def test_access_basic
    begin
       runner = nil
       assert_nothing_raised do
        runner = WLRunner.create(@username, @pg_file, @port, {:accessc => true, :debug => true })
       end
       runner.run_engine
       #verify acl contents
       assert_equal [{:plist=>PList.new(["test_access"].to_set), :priv=>"G", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"W", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"R", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"G", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"W", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"R", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"G", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"W", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"R", :rel=>"local2_at_test_access"}],
				  runner.snapshot_facts(:acl_at_test_access)
      #verify kind contents
      assert_equal [{:rel=>"local1_at_test_access", :kind=>"Extensional", :arity=>1}, {:rel=>"local2_at_test_access", :kind=>"Extensional", :arity=>2}], runner.snapshot_facts(:t_kind)

      assert_equal [{:atom1=>"1"}, {:atom1=>"2"}], runner.snapshot_facts(:local1_at_test_access)
      assert_equal [{:atom1=>"1", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"G", :plist=>Omega.instance}], runner.snapshot_facts(:local1_ext_at_test_access)
	
    ensure
      runner.clear_rule_dir
      if EventMachine::reactor_running?
        runner.stop
      end
      File.delete(@pg_file) if File.exists?(@pg_file)
    end
  end  
end

class TcAccessLocalRules < Test::Unit::TestCase
  include MixinTcWlTest
  
  def setup
    @pg = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection int local1_i@test_access(atom1*);
collection ext per local2@test_access(atom1*, atom2);
fact local2@test_access(1, 3);
fact local2@test_access(2, 4);
rule local1_i@test_access($x) :- local2@test_access($x, $y);
end
    EOF
    @username = "test_access"
    @port = "11110"
    @pg_file = "test_access_control_local_rules"
    File.open(@pg_file,"w"){ |file| file.write @pg }
  end

  def teardown    
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  def test_local_rules
    begin
       runner = nil
       assert_nothing_raised do
        runner = WLRunner.create(@username, @pg_file, @port, {:accessc => true, :debug => true })
      end
       runner.run_engine

      #what do we want to check here? that for local rules all facts get in because peer can read his own stuff
      assert_equal [{:atom1=>"1", :priv=>"G", :plist=>PList.new(["test_access"].to_set)}, {:atom1=>"2", :priv=>"G", :plist=>PList.new(["test_access"].to_set)}, {:atom1=>"1", :priv=>"R", :plist=>PList.new(["test_access"].to_set)}, {:atom1=>"2", :priv=>"R", :plist=>PList.new(["test_access"].to_set)}], runner.snapshot_facts(:local1_i_ext_at_test_access)
      assert_equal [], runner.snapshot_facts(:local1_i_at_test_access)

    ensure
      if EventMachine::reactor_running?
        runner.stop
      end
       File.delete(@pg_file) if File.exists?(@pg_file)
    end
    
  end
end

class TcAccessNonlocalRules < Test::Unit::TestCase
  include MixinTcWlTest

  def setup
    @pg1 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
collection int local3_i@test_access(atom1*, atom2*);
fact local2@test_access(1);
fact local2@test_access(2);
rule delegated1_i@p1($x) :- local2@test_access($x);
rule delegated_join_i@p1($x,$y) :- local2@test_access($x), local1@p1($y);
rule local3_i@test_access($x, $y) :- local2@test_access($x), local1@p1($y);
end
    EOF
    @username1 = "test_access"
    @port1 = "11110"
    @pg_file1 = "test_access_control_remote_rules1"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }

    @pg2 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local1@p1(atom1*);
collection int delegated1_i@p1(atom1*);
collection int delegated_join_i@p1(atom1*, atom2*);
fact local1@p1(3);
end
    EOF
    @username2 = "p1"
    @port2 = "11111"
    @pg_file2 = "test_access_control_remote_rules2"
    File.open(@pg_file2,"w"){ |file| file.write @pg2 }
  end

  def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  def test_remote_rules
    begin
      runner1 = nil
      runner2 = nil
      assert_nothing_raised do
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true })
        runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true })
      end

      runner2.tick
      runner1.tick
      runner2.tick
      runner2.tick
      runner2.tick
      runner2.tick

      #first check the collections that have direct facts inserted into them
      assert_equal [{:atom1=>"1"}, {:atom1=>"2"}], runner1.tables[:local2_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"1", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"G", :plist=>Omega.instance}], runner1.tables[:local2_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [], runner1.tables[:local3_i_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"3"}], runner2.tables[:local1_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"3", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"3", :priv=>"G", :plist=>Omega.instance}], runner2.tables[:local1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #now check delegated collections that should be created
      assert_equal [],
        runner2.tables[:deleg_from_test_access_1_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [],
        runner2.tables[:deleg_from_test_access_2_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:deleg_from_test_access_3_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #now check materialized collections from rules
      assert_equal [],
        runner2.tables[:delegated1_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:delegated_join_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner1.tables[:local3_i_ext_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now manually change acl for reading and test that tuples come over
      runner1.update_acl("local2_at_test_access","p1","R")

      runner1.tick
      runner1.tick
      runner2.tick
      runner2.tick

      assert_equal [{:deleg_from_test_access_1_1_x_0=>"1",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}, {:deleg_from_test_access_1_1_x_0=>"2",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}],
        runner2.tables[:deleg_from_test_access_1_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:deleg_from_test_access_2_1_x_0=>"1",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}, {:deleg_from_test_access_2_1_x_0=>"2",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}],
        runner2.tables[:deleg_from_test_access_2_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [{:deleg_from_test_access_3_1_x_0=>"1",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}, {:deleg_from_test_access_3_1_x_0=>"2",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}],
        runner2.tables[:deleg_from_test_access_3_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}


      #test_access doesn't have write privs, so the relation should still be empty
      assert_equal [],
        runner2.tables[:delegated1_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:delegated_join_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner1.tables[:local3_i_ext_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now give write privs to test_access at p1
      runner2.update_acl("delegated1_i_at_p1","test_access","W")
      runner2.update_acl("delegated_join_i_at_p1","test_access","W")
      runner2.tick
      runner2.tick

      assert_equal [{:atom1=>"1", :priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}, {:atom1=>"2",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}],
        runner2.tables[:delegated1_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"R", :plist=>PList.new(["p1"].to_set)},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>PList.new(["p1"].to_set)}], runner2.tables[:delegated_join_i_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      
      #test_access does not have privs to read local1@p1 so no results
      assert_equal [],
        runner1.tables[:local3_i_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now let's set that and see results finally materialize at p1
      runner2.update_acl("local1_at_p1","test_access","R")
      runner1.update_acl("local3_i_at_test_access","p1","W")
      runner1.tick
      runner1.tick

      assert_equal [{:atom1=>"1",:atom2=>"3", :priv=>"R", :plist=>PList.new(["test_access","p1"].to_set)},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>PList.new(["test_access","p1"].to_set)}], runner1.tables[:local3_i_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      #incidentally, this also means delegated_join has an updated list
      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"R", :plist=>PList.new(["test_access","p1"].to_set)},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>PList.new(["test_access","p1"].to_set)}], runner2.tables[:delegated_join_i_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }

    ensure
      File.delete(@pg_file1) if File.exists?(@pg_file1)
      File.delete(@pg_file2) if File.exists?(@pg_file2)
      if EventMachine::reactor_running?
        runner1.stop
        runner2.stop true
      end
    end

  end
end

class TcAccessExtensionalRules < Test::Unit::TestCase
  include MixinTcWlTest

  def setup
    @pg1 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
collection ext local3@test_access(atom1*, atom2*);
fact local2@test_access(1);
fact local2@test_access(2);
rule delegated1@p1($x) :- local2@test_access($x);
rule delegated_join@p1($x,$y) :- local2@test_access($x), local1@p1($y);
rule local3@test_access($x, $y) :- local2@test_access($x), local1@p1($y);
end
    EOF
    @username1 = "test_access"
    @port1 = "11110"
    @pg_file1 = "test_access_extensional1"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }

    @pg2 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local1@p1(atom1*);
collection ext delegated1@p1(atom1*);
collection ext delegated_join@p1(atom1*, atom2*);
fact local1@p1(3);
end
    EOF
    @username2 = "p1"
    @port2 = "11111"
    @pg_file2 = "test_access_extensional2"
    File.open(@pg_file2,"w"){ |file| file.write @pg2 }
  end

  def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  def test_extensional
    begin
      runner1 = nil
      runner2 = nil
      assert_nothing_raised do
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true })
        runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true })
      end

      runner2.tick
      runner1.tick
      runner2.tick
      runner2.tick
      runner2.tick
      runner2.tick

      #first check the collections that have direct facts inserted into them
      assert_equal [{:atom1=>"1"}, {:atom1=>"2"}], runner1.tables[:local2_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"1", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"G", :plist=>Omega.instance}], runner1.tables[:local2_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [], runner1.tables[:local3_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"3"}], runner2.tables[:local1_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"3", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"3", :priv=>"G", :plist=>Omega.instance}], runner2.tables[:local1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #now check delegated collections that should be created. because of extensional head they should materialize right away
      assert_equal [{:deleg_from_test_access_1_1_x_0=>"1",:priv=>"R",:plist=>Omega.instance}, {:deleg_from_test_access_1_1_x_0=>"2",:priv=>"R",:plist=>Omega.instance},{:deleg_from_test_access_1_1_x_0=>"1",:priv=>"G",:plist=>Omega.instance}, {:deleg_from_test_access_1_1_x_0=>"2",:priv=>"G",:plist=>Omega.instance}],
        runner2.tables[:deleg_from_test_access_1_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:deleg_from_test_access_2_1_x_0=>"1",:priv=>"R",:plist=>Omega.instance}, {:deleg_from_test_access_2_1_x_0=>"2",:priv=>"R",:plist=>Omega.instance},{:deleg_from_test_access_2_1_x_0=>"1",:priv=>"G",:plist=>Omega.instance}, {:deleg_from_test_access_2_1_x_0=>"2",:priv=>"G",:plist=>Omega.instance}],
        runner2.tables[:deleg_from_test_access_2_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [{:deleg_from_test_access_3_1_x_0=>"1",:priv=>"R",:plist=>Omega.instance}, {:deleg_from_test_access_3_1_x_0=>"2",:priv=>"R",:plist=>Omega.instance},{:deleg_from_test_access_3_1_x_0=>"1",:priv=>"G",:plist=>Omega.instance}, {:deleg_from_test_access_3_1_x_0=>"2",:priv=>"G",:plist=>Omega.instance}],
        runner2.tables[:deleg_from_test_access_3_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #test_access doesn't have write privs, so the relation should still be empty
      assert_equal [],
        runner2.tables[:delegated1_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:delegated_join_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner1.tables[:local3_ext_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now give write privs to test_access at p1
      runner2.update_acl("delegated1_at_p1","test_access","W")
      runner2.update_acl("delegated_join_at_p1","test_access","W")
      runner2.tick
      runner2.tick

      assert_equal [{:atom1=>"1", :priv=>"R",:plist=>Omega.instance}, {:atom1=>"2",:priv=>"R",:plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"G", :plist=>Omega.instance}],
        runner2.tables[:delegated1_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      #because this is an extensional-head relation, without grant privs on p1's local1 the result should still be empty
      assert_equal [], runner2.tables[:delegated_join_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      
      #test_access does not have privs to grant local1@p1 so no results
      assert_equal [],
        runner1.tables[:local3_ext_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now let's set that and see results still not materialize at p1 due to lack of grant
      runner2.update_acl("local1_at_p1","test_access","R")
      runner1.tick
      runner1.tick

      assert_equal [], runner2.tables[:delegated_join_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [], runner1.tables[:local3_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      #now let's set grant and finally should see results
      runner2.update_acl("local1_at_p1","test_access","G")
      runner1.update_acl("local3_at_test_access","p1","W")
      runner2.tick
      runner1.tick

      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"R", :plist=>Omega.instance},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>Omega.instance},{:atom1=>"1", :atom2=>"3", :priv=>"G", :plist=>Omega.instance},{:atom1=>"2",:atom2=>"3", :priv=>"G", :plist=>Omega.instance}], runner2.tables[:delegated_join_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }

      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"R", :plist=>Omega.instance},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>Omega.instance},{:atom1=>"1", :atom2=>"3", :priv=>"G", :plist=>Omega.instance},{:atom1=>"2",:atom2=>"3", :priv=>"G", :plist=>Omega.instance}], runner1.tables[:local3_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

    ensure
      File.delete(@pg_file1) if File.exists?(@pg_file1)
      File.delete(@pg_file2) if File.exists?(@pg_file2)
      if EventMachine::reactor_running?
        runner1.stop
        runner2.stop true
      end
    end

  end

end

