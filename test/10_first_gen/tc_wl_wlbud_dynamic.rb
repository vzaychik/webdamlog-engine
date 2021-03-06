# Test the methods inside wlbud that are never called directly from outside to
# modify dynamically webdamlog programs

$:.unshift File.dirname(__FILE__)
require_relative '../header_test'
require_relative '../../lib/webdamlog_runner'
require 'test/unit'

# Test dynamic facts addition
class Tc1WlBudAddFacts < Test::Unit::TestCase
  include MixinTcWlTest

  def  setup
    @pg = <<-EOF
peer test_add_facts=localhost:11110;
peer p1=localhost:11111;
peer p2=localhost:11112;
peer p3=localhost:11113;
collection ext persistent local@test_add_facts(atom1*);
collection ext per join_delegated@test_add_facts(atom1*);
collection int local2@test_add_facts(atom1*);
fact local@test_add_facts(1);
fact local@test_add_facts(2);
fact local@test_add_facts(3);
fact local@test_add_facts(4);
rule join_delegated@p0($x):- local@test_add_facts($x),delegated@p1($x),delegated@p2($x),delegated@p3($x);
rule local2@test_add_facts($x) :- local@test_add_facts($x);
end
    EOF
    @username = "test_add_facts"
    @port = "11110"
    @pg_file = "test_add_facts_program"
    File.open(@pg_file,"w"){ |file| file.write @pg }
  end

  def teardown
    File.delete(@pg_file) if File.exists?(@pg_file)
    ObjectSpace.each_object(WLBud::WL) do |obj|
      clean_rule_dir obj.rule_dir
    end
    ObjectSpace.garbage_collect
  end

  class KlassAddFacts < WLBud::WL; end;

  # Test add_facts in {WLBud::WL}
  def test_add_facts
    begin
      wl_obj = nil      
      assert_nothing_raised do
        wl_obj = KlassAddFacts.new(@username, @pg_file, {:port => @port})
      end
      wl_obj.run_bg
      assert_not_nil wl_obj.tables[:local_at_test_add_facts]
      assert_equal 4, wl_obj.tables[:local_at_test_add_facts].to_a.size
      valid, err = wl_obj.add_facts({ "local_at_test_add_facts" => [["5"]] })
      assert_equal 1, valid.size
      assert_equal({"local_at_test_add_facts"=>[["5"]]}, valid)
      assert_equal 0, err.size
      assert_equal({}, err)
      wl_obj.tick
      assert_equal 5, wl_obj.tables[:local_at_test_add_facts].to_a.size

      valid, err = wl_obj.add_facts({ "local_at_test_add_facts" => [["5", "6"], "", ["6"]] })
      assert_equal 1, valid.size
      assert_equal({"local_at_test_add_facts"=>[["6"]]}, valid)
      assert_equal 2, err.size
      assert_equal(
        {["local_at_test_add_facts", ["5", "6"]]=>
            "fact of arity 2 in relation local_at_test_add_facts of arity 1",
          ["local_at_test_add_facts", ""]=>
            "fact in relation local_at_test_add_facts with value \"\" should be an Array or struct instead found a String"}, err)
      wl_obj.tick
      assert_equal 6, wl_obj.tables[:local_at_test_add_facts].to_a.size
    ensure
      wl_obj.stop true
      File.delete(@pg_file) if File.exists?(@pg_file)
    end
  end
end # class TcWlWlbudAddFacts


# test update_add_collection in {WLRunner}
class TcWl2AddCollection < Test::Unit::TestCase
  include MixinTcWlTest

  def  setup
    @pg = <<-EOF
peer test_add_collection = localhost:11110;
collection ext persistent local@test_add_collection(atom1*);
collection int local2@test_add_collection(atom1*);
fact local@test_add_collection(1);
fact local@test_add_collection(2);
rule local2@test_add_collection($x) :- local@test_add_collection($x);
end
    EOF
    @username = "test_add_collection"
    @port = "11110"
    @pg_file = "test_add_collection_program"
    File.open(@pg_file,"w"){ |file| file.write @pg }
  end

  def teardown
    File.delete(@pg_file) if File.exists?(@pg_file)
    ObjectSpace.each_object(WLRunner) do |obj|
      clean_rule_dir obj.rule_dir
      obj.delete
    end
    ObjectSpace.garbage_collect
  end

  # Test add_collection in {WLBud::WL}
  def test_add_collection
    begin
      runner = nil
      assert_nothing_raised do
        runner = WLRunner.create(@username, @pg_file, @port)
      end
      runner.tick
      assert_not_nil runner.tables[:local_at_test_add_collection]
      assert_equal 2, runner.tables[:local_at_test_add_collection].to_a.size
      name, schema = nil, nil
      # #assert_nothing_raised do
      name, schema = runner.update_add_collection("collection ext persistent added@test_add_collection(field1*, field2*, field3);")
      # #end
      assert_not_nil name
      assert_not_nil schema
      assert_equal "added_at_test_add_collection", name
      assert_equal({[:field1, :field2]=>[:field3]}, schema)
    ensure
      runner.stop true
      File.delete(@pg_file) if File.exists?(@pg_file)
    end
  end
end # class TcWlAddCollection 
