$:.unshift File.dirname(__FILE__)
require_relative '../header_test_access'
require_relative '../../lib/access_runner'

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
end
    EOF
    @username = "test_access"
    @port = "11110"
    @pg_file = "test_access_control_grammar"
    File.open(@pg_file,"w"){ |file| file.write @pg }
  end

  def teardown    
    ObjectSpace.each_object(WLARunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  # check that facts have psets correctly set
  def test_access_grammar
    begin
       runner = nil
       assert_nothing_raised do
        runner = WLARunner.create(@username, @pg_file, @port, {:accessc => true, :debug => false, :noprovenance => true })
       end

      assert_equal(["policy local2 read ALL","policy local1 read p1","policy local3_i write p1"], runner.snapshot_policies)

      assert_equal [{:plist=>Omega.instance, :priv=>"R", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"G", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"W", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"R", :rel=>"acl_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"G", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"W", :rel=>"local2_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"G", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"W", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access","p1"].to_set), :priv=>"R", :rel=>"local1_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"G", :rel=>"local3_i_at_test_access"}, {:plist=>PList.new(["test_access","p1"].to_set), :priv=>"W", :rel=>"local3_i_at_test_access"}, {:plist=>PList.new(["test_access"].to_set), :priv=>"R", :rel=>"local3_i_at_test_access"}].to_set,
				  runner.snapshot_facts(:acl_at_test_access).to_set
	
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
collection ext per local1@test_access(atom1*);
collection int local3_i@test_access(atom1*);
fact local2@test_access("p1");
fact local2@test_access("p2");
policy local1 read p1;
policy local1 read p2;
end
    EOF
    @username = "test_access"
    @port = "11110"
    @pg_file = "test_access_control_grammar"
    File.open(@pg_file,"w"){ |file| file.write @pg }
  end

  def teardown    
    ObjectSpace.each_object(WLARunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  # check that facts have psets correctly set
  def test_access_grammar2
    begin
       runner = nil
       assert_nothing_raised do
        runner = WLARunner.create(@username, @pg_file, @port, {:accessc => true, :debug => false, :noprovenance => true })
       end

      assert_equal(["policy local1 read p1","policy local1 read p2"], runner.snapshot_policies)

      assert_equal([{:rel=>"acl_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"G"}, {:rel=>"acl_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"W"}, {:rel=>"acl_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"R"}, {:rel=>"local2_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"G"}, {:rel=>"local2_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"W"}, {:rel=>"local2_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"R"}, {:rel=>"local1_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"G"}, {:rel=>"local1_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"W"}, {:rel=>"local1_at_test_access",:plist=>PList.new(["test_access","p1","p2"].to_set), :priv=>"R"}, {:rel=>"local3_i_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"G"}, {:rel=>"local3_i_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"W"}, {:rel=>"local3_i_at_test_access",:plist=>PList.new(["test_access"].to_set), :priv=>"R"}], runner.tables[:acl_at_test_access].map{ |t| Hash[t.each_pair.to_a]})
	
    ensure
       runner.stop
       File.delete(@pg_file) if File.exists?(@pg_file)
    end
  end  
end
