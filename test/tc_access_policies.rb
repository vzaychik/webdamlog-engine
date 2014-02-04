$:.unshift File.dirname(__FILE__)
require 'header_test'
require_relative '../lib/webdamlog_runner'

require 'test/unit'

#Test collections get additional attributes, facts get default permissions set from acl relation
class TcAccessGrammar < Test::Unit::TestCase
  include MixinTcWlTest
  
  def setup
    @pg = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
collection ext local1@test_access(atom1*);
collection int local3_i@test_access(atom1*);
fact local2@test_access(1);
fact local2@test_access(2);
policy local2 read ALL;
policy local1 read p1;
policy local3_i write p1;
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

      assert_equal(["policy local2 read ALL","policy local1 read p1","policy local3_i write p1"], runner.snapshot_policies)

      assert_equal [{:plist=>Omega.new, :priv=>"Read", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access","p1"].to_set), :priv=>"Read", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access","p1"].to_set), :priv=>"Write", :rel=>"local3_i_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Grant", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Write", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Grant", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Write", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Grant", :rel=>"local3_i_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Read", :rel=>"local3_i_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Grant", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Write", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"Read", :rel=>"acl_at_test_access"}],
				  runner.snapshot_facts(:acl_at_test_access)
	
    ensure
       runner.stop
       File.delete(@pg_file) if File.exists?(@pg_file)
    end
  end  
end

class TcAccessGrammar2 < Test::Unit::TestCase
  include MixinTcWlTest
  
  def setup
    @pg = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
collection ext per local2@test_access(atom1*);
collection ext local1@test_access(atom1*);
collection int local3_i@test_access(atom1*);
fact local2@test_access("p1");
fact local2@test_access("p2");
policy local1 read local2@test_access;
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
  def test_access_grammar2
    begin
       runner = nil
       assert_nothing_raised do
        runner = WLRunner.create(@username, @pg_file, @port, {:accessc => true, :debug => true, :noprovenance => true })
       end

      assert_equal(["policy local1 read local2@test_access"], runner.snapshot_policies)

      assert_equal [{:rel=>"local2_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Grant"}, {:rel=>"local2_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Write"}, {:rel=>"local2_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Read"}, {:rel=>"local1_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Grant"}, {:rel=>"local1_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Write"}, {:rel=>"local1_at_test_access",:plist=>PList.new(["test_access","p1","p2"].to_set), :priv=>"Read"}, {:rel=>"local3_i_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Grant"}, {:rel=>"local3_i_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Write"}, {:rel=>"local3_i_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Read"}, {:rel=>"acl_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Grant"}, {:rel=>"acl_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Write"}, {:rel=>"acl_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"Read"}], runner.tables[:acl_at_test_access].map{ |t| Hash[t.each_pair.to_a]}
	
    ensure
       #runner.stop
       File.delete(@pg_file) if File.exists?(@pg_file)
    end
  end  
end
