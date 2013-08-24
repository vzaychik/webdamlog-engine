$:.unshift File.dirname(__FILE__)
require 'header_test'
require_relative '../lib/webdamlog_runner'

require 'test/unit'

#Test collections get additional attributes, facts get default permissions set from acl relation
class TcAccessBasic < Test::Unit::TestCase
  include MixinTcWlTest
  
  def setup
    @pg = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local1@test_access(atom1*);
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
       assert_equal [{:plist=>["test_access"].to_set, :priv=>"GrantP", :rel=>"local1_at_test_access"}, {:plist=>["test_access"].to_set, :priv=>"Write", :rel=>"local1_at_test_access"}, {:plist=>["test_access"].to_set, :priv=>"Read", :rel=>"local1_at_test_access"}, {:plist=>["test_access"].to_set, :priv=>"GrantP", :rel=>"acl_at_test_access"}, {:plist=>["test_access"].to_set, :priv=>"Write", :rel=>"acl_at_test_access"}, {:plist=>["test_access"].to_set, :priv=>"Read", :rel=>"acl_at_test_access"}],
				  runner.snapshot_facts(:acl_at_test_access)
      #verify kind contents
      assert_equal [{:rel=>"local1_at_test_access", :kind=>"Extensional", :arity=>1}], runner.snapshot_facts(:t_kind)

      assert_equal [{:atom1=>"1"}, {:atom1=>"2"}], runner.snapshot_facts(:local1_at_test_access)
      assert_equal [{:atom1=>"1", :priv=>"Read", :plist=>Omega.new}, {:atom1=>"2", :priv=>"Read", :plist=>Omega.new}], runner.snapshot_facts(:local1_ext_at_test_access)
	
    ensure
       #runner.stop
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
collection int local1@test_access(atom1*);
collection ext per local2@test_access(atom1*);
fact local2@test_access(1);
fact local2@test_access(2);
rule local1@test_access($x) :- local2@test_access($x);
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
       # assert_nothing_raised do
       runner = WLRunner.create(@username, @pg_file, @port, {:accessc => true, :debug => true })
       # end
       runner.run_engine

      #what do we want to check here? that for local rules all facts get in because peer can read his own stuff
      assert_equal [{:atom1=>"1", :priv=>"Read", :plist=>["test_access"].to_set}, {:atom1=>"2", :priv=>"Read", :plist=>["test_access"].to_set}], runner.snapshot_facts(:local1_ext_at_test_access)
      assert_equal [], runner.snapshot_facts(:local1_at_test_access)

    ensure
       #runner.stop
       File.delete(@pg_file) if File.exists?(@pg_file)
    end
    
  end
end

class TcAccessRemoteRules < Test::Unit::TestCase
  include MixinTcWlTest
  
  def setup
    @pg1 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
collection int local1@p1(atom1*);
collection int local3@p1(atom1*, atom2*);
fact local2@test_access(1);
fact local2@test_access(2);
rule local1@p1($x) :- local2@test_access($x);
rule local3@p1($x,$y) :- local2@test_access($x), local1@p1($y);
end
    EOF
    @username1 = "test_access"
    @port1 = "11110"
    @pg_file1 = "test_access_control_remote_rules1"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }

    @pg2 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection int local1@p1(atom1*);
collection int local3@p1(atom1*, atom2*);
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
       # assert_nothing_raised do
       runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => false, :debug => true })
       runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => false, :debug => true })
       # end
       runner1.run_engine
       runner2.run_engine

       runner1.tick
       runner2.tick

      #TODO what do we want to check here? that for remote rules no facts get in because there are no default permissions
      #assert_equal [], runner2.snapshot_facts(:local1_at_p1)
      assert_equal [], runner2.snapshot_facts(:local3_at_p1)

    ensure
       File.delete(@pg_file1) if File.exists?(@pg_file1)
       File.delete(@pg_file2) if File.exists?(@pg_file2)
    end
    
  end
end
