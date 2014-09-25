$:.unshift File.dirname(__FILE__)
require_relative '../header_test_access'
require_relative '../../lib/access_runner'

require 'test/unit'

class TcAccessTestFormulas < Test::Unit::TestCase
  include MixinTcWlTest

  def setup
    @pg1 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
collection int local1@test_access(atom1*);
fact local2@test_access(1);
fact local2@test_access(2);
fact local2@test_access(3);
end
    EOF
    @username1 = "test_access"
    @port1 = "11110"
    @pg_file1 = "test_access_control_formulas"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
  end

  def teardown
    ObjectSpace.each_object(WLARunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  def test_formulas
    begin
      runner1 = nil
      assert_nothing_raised do
        runner1 = WLARunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => false, :optim2 => true, :noprovenance => true })
      end

      runner1.tick

      assert_equal [{:id=>"All peers", :plist=>Omega.instance},{:id=>"test_access_B",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_A",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_D",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_C",:plist=>PList.new(["test_access"].to_set)}], runner1.tables[:formulas_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:rel=>"local2_at_test_access",:priv=>"R",:formula=>"test_access_A"},{:rel=>"local2_at_test_access",:priv=>"G",:formula=>"test_access_B"},{:rel=>"local1_at_test_access",:priv=>"R",:formula=>"test_access_C"},{:rel=>"local1_at_test_access",:priv=>"G",:formula=>"test_access_D"}], runner1.tables[:aclf_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      assert_equal [{:atom1=>"1",:priv=>"R",:plist=>Omega.instance},{:atom1=>"1",:priv=>"G",:plist=>Omega.instance},{:atom1=>"2",:priv=>"R",:plist=>Omega.instance},{:atom1=>"2",:priv=>"G",:plist=>Omega.instance},{:atom1=>"3",:priv=>"R",:plist=>Omega.instance},{:atom1=>"3",:priv=>"G",:plist=>Omega.instance}], runner1.tables[:local2_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      #now give some permissions and see the updates
      runner1.update_acl("local2_at_test_access","p1","R")
      runner1.tick
      runner1.tick

      assert_equal [{:id=>"All peers", :plist=>Omega.instance},{:id=>"test_access_B",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_A",:plist=>PList.new(["test_access","p1"].to_set)},{:id=>"test_access_D",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_C",:plist=>PList.new(["test_access"].to_set)}], runner1.tables[:formulas_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:rel=>"local2_at_test_access",:priv=>"R",:formula=>"test_access_A"},{:rel=>"local2_at_test_access",:priv=>"G",:formula=>"test_access_B"},{:rel=>"local1_at_test_access",:priv=>"R",:formula=>"test_access_C"},{:rel=>"local1_at_test_access",:priv=>"G",:formula=>"test_access_D"}], runner1.tables[:aclf_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      #now add another relation and see the updates
      runner1.update_add_collection("collection int testadd@test_access(atom1*);");
      runner1.tick

      assert_equal [{:id=>"All peers", :plist=>Omega.instance},{:id=>"test_access_B",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_A",:plist=>PList.new(["test_access","p1"].to_set)},{:id=>"test_access_D",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_C",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_F",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_E",:plist=>PList.new(["test_access"].to_set)}], runner1.tables[:formulas_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:rel=>"local2_at_test_access",:priv=>"R",:formula=>"test_access_A"},{:rel=>"local2_at_test_access",:priv=>"G",:formula=>"test_access_B"},{:rel=>"local1_at_test_access",:priv=>"R",:formula=>"test_access_C"},{:rel=>"local1_at_test_access",:priv=>"G",:formula=>"test_access_D"},{:rel=>"testadd_at_test_access",:priv=>"R",:formula=>"test_access_E"},{:rel=>"testadd_at_test_access",:priv=>"G",:formula=>"test_access_F"}], runner1.tables[:aclf_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

    ensure
      File.delete(@pg_file1) if File.exists?(@pg_file1)
      if EventMachine::reactor_running?
        runner1.stop
      end
    end

  end
end

class TcAccessTestFormulasLocal < Test::Unit::TestCase
  include MixinTcWlTest

  def setup
    @pg1 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
collection int local1_i@test_access(atom1*);
collection int local3_i@test_access(atom1*);
collection ext per local4@test_access(atom1*);
fact local2@test_access(1);
fact local4@test_access(1);
fact local4@test_access(2);
rule local1_i@test_access($x) :- local2@test_access($x);
rule local1_i@test_access($x) :- local4@test_access($x);
rule local3_i@test_access($x) :- local1_i@test_access($x), local2@test_access($x);
end
    EOF
    @username1 = "test_access"
    @port1 = "11110"
    @pg_file1 = "test_access_control_formulas_local"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
  end

  def teardown
    ObjectSpace.each_object(WLARunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  def test_local
    begin
      runner1 = nil
      assert_nothing_raised do
        runner1 = WLARunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => false, :optim2 => true, :noprovenance => true })
      end

      runner1.tick

      assert_equal [{:rel=>"local2_at_test_access",:priv=>"R",:formula=>"test_access_A"},{:rel=>"local2_at_test_access",:priv=>"G",:formula=>"test_access_B"},{:rel=>"local1_i_at_test_access",:priv=>"R",:formula=>"test_access_C"},{:rel=>"local1_i_at_test_access",:priv=>"G",:formula=>"test_access_D"},{:rel=>"local3_i_at_test_access",:priv=>"R",:formula=>"test_access_E"},{:rel=>"local3_i_at_test_access",:priv=>"G",:formula=>"test_access_F"},{:rel=>"local4_at_test_access",:priv=>"R",:formula=>"test_access_G"},{:rel=>"local4_at_test_access",:priv=>"G",:formula=>"test_access_H"}], runner1.tables[:aclf_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      #check that intensional relation on the left of the rule uses formulas
      assert_equal [{:atom1=>"1",:priv=>"G",:plist=>FormulaList.new("test_access_B test_access_H +")},{:atom1=>"1",:priv=>"R",:plist=>FormulaList.new("test_access_A test_access_G +")},{:atom1=>"2",:priv=>"G",:plist=>FormulaList.new("test_access_H")},{:atom1=>"2",:priv=>"R",:plist=>FormulaList.new("test_access_G")}], runner1.tables[:local1_i_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      assert_equal [{:formula=>"test_access_A",:val=>"R"},{:formula=>"test_access_B",:val=>"G"}], runner1.tables[:formulas_local2_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      assert_equal [{:id=>"All peers", :plist=>Omega.instance},{:id=>"test_access_B",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_A",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_D",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_C",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_F",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_E",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_H",:plist=>PList.new(["test_access"].to_set)},{:id=>"test_access_G",:plist=>PList.new(["test_access"].to_set)}], runner1.tables[:formulas_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      assert_equal [{:atom1=>"1",:priv=>"G",:plist=>FormulaList.new("test_access_B test_access_H + test_access_D *")},{:atom1=>"1",:priv=>"R",:plist=>FormulaList.new("test_access_A test_access_G + test_access_C *")}], runner1.tables[:local3_i_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

    ensure
      File.delete(@pg_file1) if File.exists?(@pg_file1)
      if EventMachine::reactor_running?
        runner1.stop
      end
    end

  end
end

class TcAccessFormulasNonlocalRules < Test::Unit::TestCase
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
    ObjectSpace.each_object(WLARunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  def test_remote_rules
    begin
      runner1 = nil
      runner2 = nil
      assert_nothing_raised do
        runner1 = WLARunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => false, :optim2 => true, :noprovenance => true })
        runner2 = WLARunner.create(@username2, @pg_file2, @port2, {:accessc => true, :debug => false, :optim2 => true, :noprovenance => true })
      end

      runner2.tick
      runner1.tick
      runner2.tick
      runner2.tick
      runner2.tick
      runner2.tick

      #first check the collections that have direct facts inserted into them
      assert_equal [{:atom1=>"1", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"1", :priv=>"G", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"2", :priv=>"G", :plist=>Omega.instance}], runner1.tables[:local2_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [], runner1.tables[:local3_i_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"3", :priv=>"R", :plist=>Omega.instance}, {:atom1=>"3", :priv=>"G", :plist=>Omega.instance}], runner2.tables[:local1_plus_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #now check delegated collections that should be created
      assert_equal [],
        runner2.tables[:deleg_from_test_access_1_1_plus_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [],
        runner2.tables[:deleg_from_test_access_2_1_plus_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:deleg_from_test_access_3_1_plus_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #now check materialized collections from rules
      assert_equal [],
        runner2.tables[:delegated1_i_plus_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:delegated_join_i_plus_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner1.tables[:local3_i_plus_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now manually change acl for reading and test that tuples come over
      runner1.update_acl("local2_at_test_access","p1","R")

      runner1.tick
      runner1.tick
      runner2.tick
      runner2.tick

      assert_equal [{:deleg_from_test_access_1_1_x_0=>"1",:priv=>"R",:plist=>FormulaList.new("test_access_A")}, {:deleg_from_test_access_1_1_x_0=>"2",:priv=>"R",:plist=>FormulaList.new("test_access_A")}],
        runner2.tables[:deleg_from_test_access_1_1_plus_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:deleg_from_test_access_2_1_x_0=>"1",:priv=>"R",:plist=>FormulaList.new("test_access_A")}, {:deleg_from_test_access_2_1_x_0=>"2",:priv=>"R",:plist=>FormulaList.new("test_access_A")}],
        runner2.tables[:deleg_from_test_access_2_1_plus_at_p1].map{ |t| Hash[t.each_pair.to_a]}
      assert_equal [{:deleg_from_test_access_3_1_x_0=>"1",:priv=>"R",:plist=>FormulaList.new("test_access_A")}, {:deleg_from_test_access_3_1_x_0=>"2",:priv=>"R",:plist=>FormulaList.new("test_access_A")}],
        runner2.tables[:deleg_from_test_access_3_1_plus_at_p1].map{ |t| Hash[t.each_pair.to_a]}

      #test_access doesn't have write privs, so the relation should still be empty
      assert_equal [],
        runner2.tables[:delegated1_i_plus_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner2.tables[:delegated_join_i_plus_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [],
        runner1.tables[:local3_i_plus_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now give write privs to test_access at p1
      runner2.update_acl("delegated1_i_at_p1","test_access","W")
      runner2.update_acl("delegated_join_i_at_p1","test_access","W")
      runner2.tick
      runner2.tick

      assert_equal [{:formula=>"test_access_A",:val=>"R"}], runner2.tables[:formulas_deleg_from_test_access_1_1_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"1", :priv=>"R",:plist=>FormulaList.new("test_access_A")}, {:atom1=>"2",:priv=>"R",:plist=>FormulaList.new("test_access_A")}],
        runner2.tables[:delegated1_i_plus_at_p1].map{|t| Hash[t.each_pair.to_a]}
      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")}], runner2.tables[:delegated_join_i_plus_at_p1].map{ |t| Hash[t.each_pair.to_a] }
      
      #test_access does not have privs to read local1@p1 so no results
      assert_equal [],
        runner1.tables[:local3_i_plus_at_test_access].map{|t| Hash[t.each_pair.to_a]}

      #now let's set that and see results finally materialize at p1
      runner2.update_acl("local1_at_p1","test_access","R")
      runner1.update_acl("local3_i_at_test_access","p1","W")
      runner1.tick
      runner1.tick

      assert_equal [{:deleg_from_p1_3_1_x_0=>"1", :deleg_from_p1_3_1_y_1=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")},{:deleg_from_p1_3_1_x_0=>"2", :deleg_from_p1_3_1_y_1=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")}], runner1.tables[:deleg_from_p1_3_1_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"1",:atom2=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")}], runner1.tables[:local3_i_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      #incidentally, this also means delegated_join has an updated list
      assert_equal [{:atom1=>"1", :atom2=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")},{:atom1=>"2",:atom2=>"3", :priv=>"R", :plist=>FormulaList.new("test_access_A p1_A *")}], runner2.tables[:delegated_join_i_plus_at_p1].map{ |t| Hash[t.each_pair.to_a] }

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

