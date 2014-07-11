$:.unshift File.dirname(__FILE__)
require '../header_test'
require_relative '../../lib/webdamlog_runner'

require 'test/unit'

=begin
class TcAccessNonlocalRules < Test::Unit::TestCase
  include MixinTcWlTest

  def setup
    @pg1 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
peer p2=localhost:11211;
collection ext per samename@test_access(atom*);
collection ext per peers@test_access(atom*);
collection int local_i@test_access(atom1*, atom2*);
fact peers@test_access("p1");
fact peers@test_access("p2");
fact samename@test_access(1);
rule local_i@test_access($x) :- peers@test_access($y), samename@$y($x);
end
    EOF
    @username1 = "test_access"
    @port1 = "11110"
    @pg_file1 = "test_access_control_remote_rules1"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }

    @pg2 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
peer p2=localhost:11211;
collection ext per samename@p1(atom*);
collection ext per peers@p1(atom*);
fact peers@p1("test_access");
fact peers@p1("p2");
fact samename@p1(2);
end
    EOF
    @username2 = "p1"
    @port2 = "11111"
    @pg_file2 = "test_access_control_remote_rules2"
    File.open(@pg_file2,"w"){ |file| file.write @pg2 }

    @pg3 = <<-EOF
peer p1=localhost:11111;
peer test_access=localhost:11110;
peer p2=localhost:11211;
collection ext per samename@p2(atom*);
collection ext per peers@p2(atom*);
fact peers@p2("test_access");
fact peers@p2("p1");
fact samename@p2(3);
end
    EOF
    @username3 = "p2"
    @port3 = "11211"
    @pg_file3 = "test_access_control_remote_rules3"
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
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:debug => true, :tag => "test_access" })
        runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:debug => true, :tag => "p1"  })
        runner3 = WLRunner.create(@username3, @pg_file3, @port3, {:debug => true, :tag => "p2"  })
      end
    ensure
      File.delete(@pg_file1) if File.exists?(@pg_file1)
      File.delete(@pg_file2) if File.exists?(@pg_file2)
      File.delete(@pg_file3) if File.exists?(@pg_file3)
      if EventMachine::reactor_running?
        runner1.stop
        runner2.stop true
        runner3.stop true
      end
    end
  end
end
=end

#Set up a test to measure performance of basic implementation


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
fact local2@test_access(3);
fact local2@test_access(4);
fact local2@test_access(5);
rule delegated1_i@p1($x) :- local2@test_access($x);
rule delegated_join_i@p1($x,$y) :- local2@test_access($x), local1@p1($y);
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
fact local1@p1(10);
fact local1@p1(11);
fact local1@p1(12);
fact local1@p1(13);
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
        #runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :mesure => true, :tag => "test_access" })
        #runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :mesure => true, :tag => "p1"  })
        runner1 = WLRunner.create(@username1, @pg_file1, @port1, {:accessc => true, :optim1 => true, :measure => true, :tag => "test_access" })
        runner2 = WLRunner.create(@username2, @pg_file2, @port2, {:accessc => true, :optim1 => true, :measure => true, :tag => "p1"  })
      end

      runner2.tick
      runner1.tick
      runner2.tick
      runner2.tick
      runner2.tick
      runner2.tick

      #now manually change acl for reading and test that tuples come over
      runner1.update_acl("local2_at_test_access","p1","Read")

      runner1.tick
      runner1.tick
      runner2.tick
      runner2.tick

      #now give write privs to test_access at p1
      runner2.update_acl("delegated1_i_at_p1","test_access","Write")
      runner2.update_acl("delegated_join_i_at_p1","test_access","Write")
      runner2.tick
      runner2.tick

      #now let's set that and see results finally materialize at p1
      runner2.update_acl("local1_at_p1","test_access","Read")
      runner1.tick
      runner1.tick

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


#class TcAccessMeasureBasicImpl < Test::Unit::TestCase
#  include MixinTcWlTest
  
#  def setup
#    @username = "testpeer_1"
#    @port = "11110"
#    @pg_file = "test_access_peer1"
#  end

#  def teardown    
#    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
#    ObjectSpace.garbage_collect
#  end

  # check that facts have psets correctly set
#  def test_access_measure
#    begin
#       runner = nil
#       assert_nothing_raised do
#        runner = WLRunner.create(@username, @pg_file, @port, {:accessc => true, :mesure => true, :metrics => true })
#       end

#      runner.run_engine

#    ensure
       #runner.stop
#       File.delete(@pg_file) if File.exists?(@pg_file)
#    end
#  end  
#end


