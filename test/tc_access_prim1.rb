$:.unshift File.dirname(__FILE__)
require 'header_test'
require_relative '../lib/webdamlog_runner'

require 'test/unit'

class TcAccessTestWriteable < Test::Unit::TestCase
  include MixinTcWlTest

  def setup
    @pg1 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
fact local2@test_access(1);
fact local2@test_access(2);
rule delegated1_i@p1($x) :- local2@test_access($x);
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

  def test_writeable
    begin
      runner1 = nil
      runner2 = nil
      assert_nothing_raised do
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true, :optim1 => true })
        runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true, :optim1 => true })
      end

      runner1.tick
      runner2.tick
      runner1.tick
      runner2.tick
      runner1.tick
      runner2.tick

      #check that writeable on each peer has nothing
      assert_equal [], runner1.tables[:writeable_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [], runner2.tables[:writeable_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [],
      runner2.tables[:delegated1_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}


      #now give some write permissions and see it come through
      runner1.update_acl("local2_at_test_access","p1","R")
      runner2.update_acl("delegated1_i_at_p1","test_access","W")
      runner1.tick
      runner1.tick
      runner2.tick
      runner2.tick
      runner1.tick
      runner2.tick
      runner1.tick
      runner2.tick
      runner1.tick
      runner2.tick

      assert_equal [{:rel=>"delegated1_i_at_p1",:peer=>"p1"}], runner1.tables[:writeable_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"1", :priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}, {:atom1=>"2",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}],
        runner2.tables[:delegated1_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}


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


class TcAccessCapc < Test::Unit::TestCase
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

  def test_capc
    begin
      runner1 = nil
      runner2 = nil
      assert_nothing_raised do
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true, :optim1 => true })
        runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true, :optim1 => true })
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

      #test_access doesn't have write privs, so the relation should still be empty including intermediary ones because of writeable
      assert_equal [],
        runner2.tables[:deleg_from_test_access_2_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:deleg_from_test_access_3_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}

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
      runner1.tick
      runner2.tick
      runner1.tick
      runner2.tick
      runner2.tick

      assert_equal [{:deleg_from_test_access_3_1_x_0=>"1", :priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}, {:deleg_from_test_access_3_1_x_0=>"2",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}],
        runner2.tables[:deleg_from_test_access_3_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [{:atom1=>"3", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"3", :priv=>"G", :plist=>Omega.instance}], runner2.tables[:rext_2_local1_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      assert_equal [{:atom1=>"1", :priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}, {:atom1=>"2",:priv=>"R",:plist=>PList.new(["test_access","p1"].to_set)}],
        runner2.tables[:delegated1_i_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"R", :plist=>PList.new(["p1"].to_set)},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>PList.new(["p1"].to_set)}], runner2.tables[:delegated_join_i_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      
      #test_access does not have privs to read local1@p1 so no results
      assert_equal [],
        runner1.tables[:local3_i_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now let's set that and see results finally materialize at p1
      runner2.update_acl("local1_at_p1","test_access","R")
      runner2.tick
      runner1.tick
      runner1.tick

      assert_equal [{:priv=>"R", :plist=>PList.new(["test_access","p1"].to_set)}], runner2.tables[:capc_2__at_p1].map{ |t| Hash[t.each_pair.to_a] }

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


class TcAccessExtensionalRulesOptim1 < Test::Unit::TestCase
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

  def test_extensional_optim1
    begin
      runner1 = nil
      runner2 = nil
      assert_nothing_raised do
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true, :optim1 => true })
        runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => true, :optim1 => true })
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

      #now check delegated collections that should be created
      assert_equal [],
        runner2.tables[:deleg_from_test_access_2_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:deleg_from_test_access_3_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #now check materialized collections from rules
      assert_equal [],
        runner2.tables[:delegated1_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:delegated_join_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner1.tables[:local3_ext_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now manually change acl for reading and test that tuples come over
      runner1.update_acl("local2_at_test_access","p1","R")

      runner1.tick
      runner1.tick
      runner2.tick
      runner2.tick

      #test_access doesn't have write privs, so the relation should still be empty due to writeable
      assert_equal [],
        runner2.tables[:deleg_from_test_access_2_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:deleg_from_test_access_3_1_ext_at_p1].map{ |t| Hash[t.each_pair.to_a]}

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
      runner1.tick
      runner2.tick
      runner1.tick
      runner2.tick
      runner1.tick
      runner2.tick

      assert_equal [{:atom1=>"1", :priv=>"G",:plist=>Omega.instance}, {:atom1=>"1", :priv=>"R",:plist=>Omega.instance}, {:atom1=>"2",:priv=>"G",:plist=>Omega.instance},{:atom1=>"2",:priv=>"R",:plist=>Omega.instance}],
        runner1.tables[:rext_1_local2_at_test_access].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [{:atom1=>"1", :priv=>"G",:plist=>Omega.instance}, {:atom1=>"1",:priv=>"R",:plist=>Omega.instance},{:atom1=>"2", :priv=>"G",:plist=>Omega.instance}, {:atom1=>"2",:priv=>"R",:plist=>Omega.instance}],
        runner2.tables[:delegated1_ext_at_p1].map{|t| Hash[t.each_pair.to_a]}
      #because this is an extensional-head relation, without grant privs on p1's local1 the result should still be empty
      assert_equal [], runner2.tables[:delegated_join_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      
      #test_access does not have privs to read local1@p1 so no results
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
      runner2.tick
      runner1.tick

      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"G", :plist=>Omega.instance},{:atom1=>"1",:atom2=>"3", :priv=>"R", :plist=>Omega.instance},{:atom1=>"2", :atom2=>"3", :priv=>"G", :plist=>Omega.instance},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>Omega.instance}], runner2.tables[:delegated_join_ext_at_p1].map{ |t| Hash[t.each_pair.to_a] }

      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"G", :plist=>Omega.instance},{:atom1=>"1",:atom2=>"3", :priv=>"R", :plist=>Omega.instance},{:atom1=>"2", :atom2=>"3", :priv=>"G", :plist=>Omega.instance},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>Omega.instance}], runner1.tables[:local3_ext_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

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

