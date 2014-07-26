$:.unshift File.dirname(__FILE__)
require_relative '../header_test'
require_relative '../../lib/webdamlog_runner'

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
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end

  def test_formulas
    begin
      runner1 = nil
      assert_nothing_raised do
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :debug => true, :optim2 => true, :noprovenance => true })
      end

      runner1.tick

      #check that formulas has the peer itself as one symbol
      assert_equal [{:plist=>["test_access"],:id=>"test_access_0"}], runner1.tables[:formulas_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:rel=>"local2_at_test_access",:priv=>"Grant",:plist=>"test_access_0"}, {:rel=>"local2_at_test_access",:priv=>"Read",:plist=>"test_access_0"}, {:rel=>"local1_at_test_access",:priv=>"Grant",:plist=>"test_access_0"}, {:rel=>"local1_at_test_access",:priv=>"Read",:plist=>"test_access_0"}, {:rel=>"acl_at_test_access",:priv=>"Grant",:plist=>"test_access_0"}, {:rel=>"acl_at_test_access",:priv=>"Read",:plist=>"test_access_0"}], runner1.tables[:aclf_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:atom1=>"1",:priv=>"Read",:plist=>Omega.new},{:atom1=>"1",:priv=>"Grant",:plist=>Omega.new},{:atom1=>"2",:priv=>"Read",:plist=>Omega.new},{:atom1=>"2",:priv=>"Grant",:plist=>Omega.new},{:atom1=>"3",:priv=>"Read",:plist=>Omega.new},{:atom1=>"3",:priv=>"Grant",:plist=>Omega.new}], runner1.tables[:local2_plus_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

      #now give some permissions and see more symbols
      runner1.update_acl("local2_at_test_access","p1","Read")
      runner1.tick
      runner1.tick

      assert_equal [{:plist=>["test_access"],:id=>"test_access_0"},{:plist=>["test_access","p1"],:id=>"test_access_1"}], runner1.tables[:formulas_at_test_access].map{ |t| Hash[t.each_pair.to_a] }
      assert_equal [{:rel=>"local2_at_test_access",:priv=>"Grant",:plist=>"test_access_0"}, {:rel=>"local2_at_test_access",:priv=>"Read",:plist=>"test_access_1"}, {:rel=>"local1_at_test_access",:priv=>"Grant",:plist=>"test_access_0"}, {:rel=>"local1_at_test_access",:priv=>"Read",:plist=>"test_access_0"}, {:rel=>"acl_at_test_access",:priv=>"Grant",:plist=>"test_access_0"}, {:rel=>"acl_at_test_access",:priv=>"Read",:plist=>"test_access_0"}], runner1.tables[:aclf_at_test_access].map{ |t| Hash[t.each_pair.to_a] }

    ensure
      File.delete(@pg_file1) if File.exists?(@pg_file1)
      if EventMachine::reactor_running?
        runner1.stop
      end
    end

  end
end
