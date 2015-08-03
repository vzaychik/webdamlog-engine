$:.unshift File.dirname(__FILE__)
require_relative '../header_test'
require_relative '../../lib/access_runner'

require 'test/unit'

# this test case is to check following: (where a is ext and b is int)
# If we have three relations
#a@peer($x) :- c@peer($x)
#b_i@peer($x) :- c@peer($x)
# if we delete a fact from 'c', it should be deleted from 'b' as well but not from 'a'

class TcDeleteFactRemote < Test::Unit::TestCase
  include MixinTcWlTest  
  
  #setting up the rules inside a file
  def setup
    @pg1 = <<-EOF
        peer p1=localhost:11115;
        peer p2=localhost:11116;
        collection ext per rel1@p1(atom1*);
        collection ext per rel3@p1(atom1*);
        collection int rel2_i@p1(atom1*);
        fact rel1@p1(3);
        fact rel1@p1(5);
        rule rel2_i@p1($x) :- rel1@p1($x);
        rule rel3@p1($x) :- rel1@p1($x);
        rule rel2@p2($x) :- rel1@p1($x); # these are the rules which are the basis for this test
        rule rel3_i@p2($x) :- rel1@p1($x); # rel2 is ext, rel 1 and rel3 are intentional, infact relation 3 is a direct copy(view) of relation 1
    end
    EOF
    @username1 = "p1"
    @port1 = "11115"
    @pg_file1 = "New_delete_fact_test"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
    
    @pg2 = <<-EOF
    peer p1=localhost:11115;
    peer p=localhost:11116;
    collection ext per rel2@p2(atom1*);
    collection int rel3_i@p2(atom1*);
    end
    EOF
    @username2 = "p2"
    @port2 = "11116"
    @pg_file2 = "New2_delete_fact_test"
    File.open(@pg_file2,"w"){ |file| file.write @pg2 }
  end

  def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end
  
  def test_remove_priviledge_adv
    runner1 = nil
    runner2 = nil
    assert_nothing_raised do
      runner1 = WLARunner.create(@username1, @pg_file1, @port1, {:debug => true, :noprovenance => true })
      runner2 = WLARunner.create(@username2, @pg_file2, @port2, {:debug => true, :noprovenance => true })
    end
    
    runner2.tick
    runner1.tick
    runner1.tick    
    runner2.tick
    runner1.tick
    runner2.tick
    runner1.tick
    
    #checking that data is materialized
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}], runner1.tables[:rel1_at_p1].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}], runner1.tables[:rel2_i_at_p1].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}], runner1.tables[:rel3_at_p1].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}],runner2.tables[:rel2_at_p2].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}],runner2.tables[:rel3_i_at_p2].map{ |t| Hash[t.each_pair.to_a]}
        
    #delete the facts from relation 1
    runner1.delete_facts({"rel1_at_p1"=>[["3"]]})

    runner1.tick
    runner1.tick
    assert_equal [{:atom1=>"5"}], runner1.tables[:rel1_at_p1].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [{:atom1=>"5"}], runner1.tables[:rel2_i_at_p1].map{ |t| Hash[t.each_pair.to_a]}    
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}], runner1.tables[:rel3_at_p1].map{ |t| Hash[t.each_pair.to_a]}

    # running the peers
    runner2.tick
    runner1.tick
    runner2.tick
    runner1.tick
    runner2.tick
    runner1.tick
    
    # after removing the facts, nothing should be available in rel3 as it is a view and should have been deleted with deletion of facts from relation 1 above
    assert_equal [{:atom1=>"5"}], runner2.tables[:rel3_i_at_p2].map{ |t| Hash[t.each_pair.to_a]}
    
    # rel2 should be same as it is an extentional relation and there is no effect on the data inside relation 2 with deletion of facts in relation 1
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}],runner2.tables[:rel2_at_p2].map{ |t| Hash[t.each_pair.to_a]}

    runner1.delete_facts({"rel1_at_p1"=>[["5"]]})
    runner1.tick
    runner1.tick
    runner2.tick
    runner2.tick

    assert_equal [], runner1.tables[:rel1_at_p1].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [], runner1.tables[:rel2_i_at_p1].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [], runner2.tables[:rel3_i_at_p2].map{ |t| Hash[t.each_pair.to_a]}
    
  ensure
    File.delete(@pg_file1) if File.exists?(@pg_file1)
    File.delete(@pg_file2) if File.exists?(@pg_file2)
    if EventMachine::reactor_running?
      runner1.stop
      runner2.stop
    end
    
  end
  
end

class TcDeleteFactTwoSources < Test::Unit::TestCase
  include MixinTcWlTest  
  
  #setting up the rules inside a file
  def setup
    @pg1 = <<-EOF
        peer p1=localhost:11115;
        peer p2=localhost:11116;
        peer p3=localhost:11118;
        collection ext per rel1@p1(atom1*);
        fact rel1@p1(3);
        fact rel1@p1(5);
        rule rel3_i@p3($x) :- rel1@p1($x);
    end
    EOF
    @username1 = "p1"
    @port1 = "11115"
    @pg_file1 = "Twosources_delete_fact_test"
    File.open(@pg_file1,"w"){ |file| file.write @pg1 }
    
    @pg2 = <<-EOF
    peer p1=localhost:11115;
    peer p2=localhost:11116;
    peer p3=localhost:11118;
    collection ext per rel2@p2(atom1*);
    fact rel2@p2(1);
    fact rel2@p2(5);
    rule rel3_i@p3($x) :- rel2@p2($x);
    end
    EOF
    @username2 = "p2"
    @port2 = "11116"
    @pg_file2 = "Twosources2_delete_fact_test"
    File.open(@pg_file2,"w"){ |file| file.write @pg2 }

    @pg3 = <<-EOF
    peer p1=localhost:11115;
    peer p2=localhost:11116;
    peer p3=localhost:11118;
    collection int rel3_i@p3(atom1*);
    end
    EOF
    @username3 = "p3"
    @port3 = "11118"
    @pg_file3 = "Twosources3_delete_fact_test"
    File.open(@pg_file3,"w"){ |file| file.write @pg3 }

  end

  def teardown
    ObjectSpace.each_object(WLRunner){ |obj| obj.delete }
    ObjectSpace.garbage_collect
  end
  
  def test_remote_twosources
    runner1 = nil
    runner2 = nil
    runner3 = nil
    assert_nothing_raised do
      runner1 = WLARunner.create(@username1, @pg_file1, @port1, {:debug => true, :noprovenance => true })
      runner2 = WLARunner.create(@username2, @pg_file2, @port2, {:debug => true, :noprovenance => true })
      runner3 = WLARunner.create(@username3, @pg_file3, @port3, {:debug => true, :noprovenance => true })
    end

    runner3.tick
    runner1.tick    
    runner2.tick
    runner3.tick
    runner1.tick    
    runner2.tick
    runner3.tick
    runner3.tick
    
    #checking that data is materialized
    assert_equal [{:atom1=>"3"}, {:atom1=>"5"}], runner1.tables[:rel1_at_p1].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [{:atom1=>"1"}, {:atom1=>"5"}], runner2.tables[:rel2_at_p2].map{ |t| Hash[t.each_pair.to_a]}
    assert_equal [{:atom1=>"1"}, {:atom1=>"3"}, {:atom1=>"5"}].to_set,runner3.tables[:rel3_i_at_p3].map{ |t| Hash[t.each_pair.to_a]}.to_set
        
    #delete the facts from relation 1
    runner1.delete_facts({"rel1_at_p1"=>[["5"]]})

    puts "deleting facts from rel1_at_p1"
    runner1.tick
    assert_equal [{:atom1=>"3"}], runner1.tables[:rel1_at_p1].map{ |t| Hash[t.each_pair.to_a]}

    # running the peers
    runner1.tick
    runner2.tick
    runner3.tick
    
    #since 5 is derived from two sources, it should still remain in rel3
    assert_equal [{:atom1=>"1"}, {:atom1=>"3"}, {:atom1=>"5"}].to_set,runner3.tables[:rel3_i_at_p3].map{ |t| Hash[t.each_pair.to_a]}.to_set

    #now delete from the other source
    runner2.delete_facts({"rel2_at_p2"=>[["5"]]})
    runner2.tick
    runner3.tick
    runner2.tick
    runner3.tick
    assert_equal [{:atom1=>"1"}, {:atom1=>"3"}].to_set,runner3.tables[:rel3_i_at_p3].map{ |t| Hash[t.each_pair.to_a]}.to_set
  ensure
    File.delete(@pg_file1) if File.exists?(@pg_file1)
    File.delete(@pg_file2) if File.exists?(@pg_file2)
    if EventMachine::reactor_running?
      runner1.stop
      runner2.stop
      runner3.stop

    end
    
  end
  
end

