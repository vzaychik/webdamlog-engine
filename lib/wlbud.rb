# -*- coding: utf-8 -*- ####License####
#  File name wlbud.rb
#  Copyright © by INRIA
#
#  Contributors : Webdam Team <webdam.inria.fr>
#       Emilien Antoine <emilien[dot]antoine[@]inria[dot]fr>
#
#   WebdamLog - 30 juin 2011
#
#   Encoding - UTF-8
# ####License####

# :title:WLBud WLBud is a Ruby Module that simulates WebdamLog behavior using
# Bud.
module WLBud

  PATH_LIB = File.expand_path(File.dirname(__FILE__))
  PATH_WLBUD = File.expand_path("wlbud/", PATH_LIB)
  PATH_CONFIG = File.expand_path("config/", PATH_LIB)
  RULE_DIR_NAME = "wlrule_to_bud"
  PATH_BUD = File.expand_path("bud/", PATH_LIB)

  # control bud gem version
  require "#{PATH_WLBUD}/version"
  require 'rubygems'
  gem 'bud', ">= #{WLBud::BUD_GEM_VERSION}"
  require 'bud'
  require 'bud/viz_util'
  require 'polyglot'
  require 'treetop'
  require 'yaml'
  require 'prettyprint'
  # stdlib
  require 'set'
  require 'benchmark'

  # file project
  require "#{PATH_WLBUD}/wlprogram"
  require "#{PATH_WLBUD}/wlpacket"
  require "#{PATH_WLBUD}/wlerror"
  require "#{PATH_WLBUD}/wlchannel"
  require "#{PATH_WLBUD}/wlvocabulary"
  # file project: automatically generated by polyglot but could also be compiled
  # via tt
  require "#{PATH_WLBUD}/wlgrammar"
  require "#{PATH_WLBUD}/provenance/graph"
  require "#{PATH_WLBUD}/provenance/node"
  require "#{PATH_WLBUD}/monkeypatch"
  # file tool project
  require "#{PATH_WLBUD}/tools/wltools"
  require "#{PATH_WLBUD}/tools/wl_measure"

  # Override bud methods
  require "#{PATH_LIB}/budoverride"

  # PENDING remove class to force user to create a new class that include WLBud.
  #   It is very unlikely that any user wants to instantiate this class directly
  #   since all the method adding(and so the rules) would be share by all the
  #   instances.
  #
  # Alternative: we could change the code to add methods to instance of objects
  #  instead of the class (lots of refactoring)
  class WL
    include WLBud

    # The name of the peer
    attr_reader :peername
    # The name of the file to read with the program
    attr_reader :filename
    attr_reader :options, :wl_program, :rules_to_delegate, :relation_to_declare, :program_loaded, :seed_to_sprout, :new_sprout_rules, :sprout_rules
    # the directory where the peer write its rules
    attr_reader :rule_dir
    attr_reader :filter_delegations, :pending_delegations
    # provenance used for deletion if true
    attr_reader :provenance, :provenance_graph

    # TODO: define the following attributes only if options[:wl_test] @return
    #   the content returned by read_packet_channel at the beginning of the tick
    #   (an array of WLPacketData)
    attr_reader :test_received_on_chan
    # A copy of the packet send on the channel in its serialized form that is an
    #   array as described in WLChannel serialize for channel that is: [[@dest,[@peer_name.to_s,@src_time_stamp.to_s,{:facts=>@facts,:rules=>@rules,:declarations=>@declarations}]]]
    attr_reader :test_send_on_chan
    attr_reader :wl_callback, :wl_callback_step
    attr_reader :measure_obj

    private

    # Make program is called in the initializer of the WL instance. Its role is
    # to create the bud structure corresponding to the wl_program instance
    # loaded.
    #
    # In detail, it create and add methods to this class. The methods created
    # have a name that correspond at a pattern that will be recognized by bud
    # such as __bootstrap__... or __bloom__... It also call the table or scratch
    # methods needed to declare the bud collection to use for this program
    #
    # TODO: add in schema init support for channel to declare new channel other
    # than the builtin :chan
    #
    def make_bud_program
      local_colls = @wl_program.wlcollections.map { |name,coll| coll }
      local_colls.each { |lcol| add_collection lcol }
      # :delay_fact_loading is used in application to delay facts loading when
      # wrappers needs to be defined and bind before we can add facts
      if @options[:delay_fact_loading]
        @program_loaded = false
      else
        generate_bootstrap(@wl_program.wlfacts,@wl_program.wlcollections)
        @program_loaded = true
      end
      local_rules = @wl_program.rule_mapping.map { |id,arr_rules| arr_rules.first }
      local_rules.each { |lrule| install_rule lrule }
    end

    public

    # if :delay_fact_loading is true you should call this to evaluate facts in
    # the bootstrap program. This will insert all the facts parsed by the
    # program from the beginning.
    def load_bootstrap_fact
      self.sync_do do
        @wl_program.wlfacts.each { |fact| add_facts(fact) }
        @program_loaded = true
      end
    end
    

    # This method will translate one wlrule in parameter into Bud rule format
    # and make bud evaluate it as method of its class. It return the name of the
    # block created that is the name of the rule in bud.
    #
    # ==== Remark
    #
    # Because of new 0.9.1 bud evaluation system, it is needed to create a file
    # in which bud is supposed to read the rule instead of just reading a block
    # dynamically created.
    def translate_rule(wlrule)
      raise "Impossible to add in bud a rule that is either unbound or non-local" unless @wl_program.bound_n_local?(wlrule)
      puts "Adding a rule: #{wlrule}" if @options[:debug]
      @wl_program.disamb_peername!(wlrule)
      rule = "#{@wl_program.translate_rule_str(wlrule)}"
      name = "webdamlog_#{@peername}_#{wlrule.rule_id}"
      install_bud_rule rule, name
      @rule_installed << wlrule
      # the last element is the bud name for the block created
      return wlrule.rule_id, wlrule.show_wdl_format, "__bloom__#{name}"
    end

    # Install any rule given in a bud format. This is not the proper method to
    # insert rule in Webdamlog you should use translate_rule that takes a
    # wlrule.
    #
    # Take care of the fact that it allows to insert any kind of rule that may
    # break the Webdamlog semantics. For this reason the provenance of such
    # rules is not supported and may even break the consistency of the
    # provenance for the whole program, for instance if this rule updates
    # Webdamlog relations.
    def install_bud_rule bud_rule, name
      if name.nil?
        if @@bud_custom_rule_id.nil?
          @@bud_custom_rule_id = 0
        else
          @@bud_custom_rule_id = @@bud_custom_rule_id + 1
        end
        str = build_string_rule_to_include("bud_custom_rule_#{@@bud_custom_rule_id}", bud_rule)
      else
        str = build_string_rule_to_include(name, bud_rule)
      end  
      fullfilename = File.join(@rule_dir,name)
      raise WLErrorPeerId, "there must be an error in unique id: #{name} of this rule: \n #{bud_rule} \n \
engine is trying to write this new rule in an existing file: #{fullfilename}" if File.exists?(fullfilename)
      fout = File.new("#{fullfilename}", "w+")
      fout.puts "#{str}"
      fout.close
      if @options[:debug]
        puts "Content of the tmp file is:\n#{File.readlines(fullfilename).each{|f| f }}\n"
      end
      load fullfilename
      @need_rewrite_strata = true      
    end

    # Build the bloom block to insert in bud with the given rule inside and as
    # name of the block "sym_name"
    def build_string_rule_to_include (name, rule)
      sym_name = name.to_sym unless name.is_a?(Symbol)
      # Does not require to load anything since it is suppose to be loaded in
      # the good environment str = "require '#{__FILE__}'\n"
      str = "class #{self.class}\n"
      str << "\tbloom :#{sym_name} do\n"
      str << "\t\t#{rule}\n"
      str << "\tend\n"
      str << "end"
      return str
    end

    # Used to add a new relation into bud from a wlcollection to declare. Should
    # be used to declare all collection that should be declared in a state block
    # in bloom.
    #
    # @param [WLCollection] wlcollection that should be declared in bud @param
    # colltype must be a sub class of Bud::Collection. It is used to force the
    # declaration of the given type of Bud Collection for this WLCollection. Use
    # it in test only as the method is supposed to parse correctly the
    # WLCollection @param args optional args if colltype is a channel then args
    # could be "loopback"
    #
    # @param [String] colltype must be a sub class of Bud::Collection i.e
    # "table, scratch or channel". It is used to force the declaration of the
    # given type of Bud Collection for this WLCollection. Use it in test only as
    # the method is supposed to parse correctly the WLCollection @param args
    # optional args if colltype is a channel then args could be "loopback"
    #
    def schema_init(wlcollection, colltype=nil, *args)
      name = wlcollection.atom_name.to_sym
      if colltype.nil?
        if wlcollection.persistent? or wlcollection.rel_type.intensional?
          self.table(name,wlcollection.schema)
        else
          self.scratch(wlcollection.atom_name.to_sym,wlcollection.schema)
        end
      else
        # Force the type of the collection to declare (for test only)
        if colltype=="table"
          self.table(name,wlcollection.schema)
        else if colltype=="scratch"
            self.scratch(name,wlcollection.schema)
          else if colltype=="channel"
              if args.first=="loopback"
                self.channel(name,wlcollection.schema,true)
              else
                self.channel(name,wlcollection.schema)
              end
            else
              raise WLError, "trying to force the type of a collection to #{colltype} that is a non-supported format"
            end
          end
        end
      end # if colltype.nil?
      return @tables[name].tabname, @tables[name].schema
    end # schema_init

    # Adds dynamically facts @return valid, err
    def add_facts(wl_facts)
      converted_facts = convert_facts_into_valid_hash wl_facts
      return insert_facts_in_coll(converted_facts)
    end
    
    # Delete facts strategy for deletion, if @provenance is true then
    # propagation algorithm is used otherwise re-computation is performed
    #  @return valid, err
    def delete_facts(wl_facts)
      converted_facts = convert_facts_into_valid_hash wl_facts
      return delete_facts_in_coll(converted_facts)
    end

    # It will dynamically add a collection to the program
    #
    # * +wlpg_relation+ is a string representing the rule in the wl_program file
    #   format(wlgrammar). @return [String, Hash] name, schema of the collection
    #   added
    #
    def add_collection(wlpg_relation)
      if wlpg_relation.is_a?(WLBud::WLCollection)
        collection = wlpg_relation
      else
        collection = @wl_program.parse(wlpg_relation, true)
      end
      raise WLErrorProgram, "parse relation and get #{collection.class}" unless collection.is_a?(WLBud::WLCollection)
      valid, msg = @wl_program.valid_collection? collection
      raise WLErrorProgram, msg unless valid
      puts "Adding a collection: \n #{collection.show_wdl_format}" if @options[:debug]
      name, schema = self.schema_init(collection)
      @collection_added = true
      return name.to_s, schema
    end

    # Takes in a string representing a WLRule, * parses it * rewrite it * adds
    #   its local part to the engine
    #
    # @raise [WLError] if something goes wrong @return [Array] rule_id, rule
    # string of the local rule installed or nil if the rule is fully delegated.
    def add_rule(wlpg_rule)
      # parse
      wlrule = @wl_program.parse(wlpg_rule, true)
      raise WLErrorProgram, "parse rule and get #{wlrule.class}" unless wlrule.is_a?(WLBud::WLRule)
      # rewrite and add it to the engine
      install_rule wlrule
    end

    private

    # rewrite a parsed wlrule and install it in the engine
    #  !@attributes [WBud::WLRule] rule as an object
    def install_rule wlrule
      if @wl_program.bound_n_local?(wlrule)
        return translate_rule(wlrule)
      else # rewrite
        @wl_program.rewrite_rule(wlrule)
        localcolls = @wl_program.flush_new_local_declaration
        if localcolls.empty? # if a fully non-local rule has been parsed
          @rules_to_delegate.merge!(@wl_program.flush_new_delegations_to_send){|key,oldv,newv| oldv += newv}
        else
          raise WLError, "one intermediary collection should have been generated while splitting a non-local rule instead of #{localcolls.length}" unless localcolls.length == 1
          intercoll = localcolls.first
          rel_name, rel_schema = add_collection(intercoll)
          localrules = @wl_program.flush_new_rewritten_local_rule_to_install
          localseeds = @wl_program.flush_new_seed_rule_to_install
          if not localrules.empty?
            raise WLError, "exactly one local rule should have been generated while splitting a non-local rule instead of #{localrules.length}" unless localrules.length == 1
            raise WLError, "if the rule is rewritable into bud it cannot contains seeds" unless localseeds.empty?            
            local_rule = localrules.first
            @relation_to_declare.merge!(@wl_program.flush_new_relations_to_declare_on_remote_peer){ |key,oldv,newv| oldv += newv }
            @rules_to_delegate.merge!(@wl_program.flush_new_delegations_to_send){|key,oldv,newv| oldv += newv}
            return translate_rule(local_rule)            
          elsif not localseeds.empty?
            raise WLError, "exactly one local rule should have been generated while splitting a non-local rule instead of #{localrules.length}" unless localseeds.length == 1
            localseed = localseeds.first
            local_rule = localseed.first
            localseed << rel_name
            @seed_to_sprout << localseed
            return translate_rule(local_rule)
          else
            raise WLError, ""
          end
        end
      end
    end

    # The generate_bootstrap method creates an array containing all extensional
    # facts information that can be read by the rule_init method (private) of
    # WLBud(see WLBud initializer).
    #
    # This create the block called bootstrap containing the fact for the initial
    # state of the peer.
    #
    # TODO optimize @wlfacts : transform it into a hash with
    # key=collection_name, value=array of facts in col. This will avoid a lot of
    # overhead.
    #
    def generate_bootstrap(facts,collections)
      if collections.empty? then puts "no relations yet..." if @options[:debug]; return; end
      if facts.empty? then puts "no facts yet..." if @options[:debug]; return; end
      str="{\n"
      collections.each_value {|wlcollection|
        tbl=[]
        @wl_program.disamb_peername!(wlcollection)
        facts.each {|wlf| tbl << wlf.content if wlf.fullrelname.eql?(wlcollection.atom_name)}
        str << "#{wlcollection.atom_name} <= " + tbl.inspect + ";\n"
      }
      str << "}"
      block = eval("Proc.new" + str)
      # #this is the same as what is done in bootstrap method in monkeypatch.rb
      meth_name = "__bootstrap__#{self.class.to_s}".to_sym
      self.class.send(:define_method, meth_name, block)
    end

    # Different structures to represent facts could be used, this method return
    # the hash with relation name as key and array of tuples(a tuple is also an
    # array).
    def convert_facts_into_valid_hash wl_facts
      if wl_facts.is_a? Hash
        valid, msg = WLPacketData.valid_hash_of_facts wl_facts
        if valid
          converted_facts = wl_facts
        else
          raise WLErrorTyping, msg
        end
      else
        if wl_facts.is_a? WLBud::WLFact
          fact = {wl_facts.fullrelname => [wl_facts.content] }
          converted_facts = convert_facts_into_valid_hash fact
        elsif wl_facts.is_a? String
          fact = @wl_program.parse(wl_facts, true)
          if fact.is_a? WLBud::WLFact
            converted_facts = convert_facts_into_valid_hash fact
          else
            raise WLErrorTyping, "fact string is not considered as a fact construct, but is #{fact.class} : #{fact}"
          end
        else
          raise WLErrorTyping, "fact is not considered as a fact construct, but is of class #{wl_facts.class}"
        end
      end
      return converted_facts
    end

    # Insert facts in collections according to messages received from channel.
    # facts should respect {WLPacketData.valid_hash_of_facts} format
    #
    # Collections in which to add facts are suppose to support <+ operator
    #
    # @return [Hash, Hash] valid and error, valid is a list of facts that have
    # been successfully inserted, err is a list of facts that has not been
    # insert due to error in the format !{["relation_name", [tuple]] => "error
    # message"}
    #
    # TODO customize according to the type of relation in which facts are
    # inserted
    #
    def insert_facts_in_coll(facts)
      valid = {}
      err = {}
      facts.each_pair do |k,tuples|
        relation_name = k
        # translate into internal relation name and check for existence of
        # relation
        relation_name = k.gsub(/@/, "_at_") if k.to_s.include?('@')
        if @wl_program.wlcollections.has_key? relation_name
          arity = @wl_program.wlcollections[relation_name].arity
          tuples.each do |tuple|
            if tuple.is_a? Array or tuple.is_a? Struct
              if tuple.size == @wl_program.wlcollections[relation_name].arity
                begin
                  tables[relation_name.to_sym] <+ [tuple]
                  (valid[relation_name] ||= []) << tuple
                rescue StandardError => error
                  err[[k,tuple]]=error.inspect
                end
              else
                err[[k,tuple]] = "fact of arity #{tuple.size} in relation #{k} of arity #{arity}"
              end
            else
              err[[k,tuple]] = "fact in relation #{k} with value \"#{tuple}\" should be an Array or struct instead found a #{tuple.class}"
            end
          end # tuples.each do |tuple|
        else
          err[[k,tuples]] = "relation name #{k} translated to #{relation_name} has not been declared previously"
        end
      end # facts.each_pair
      return valid, err
    end # insert_updates

    
    # Delete facts from collections
    #  facts should be a hash {relname=>[tuples,...]}
    # @return valid, err
    def delete_facts_in_coll facts
      valid = {}
      err = {}
      facts.each_pair do |rel_name,tuples|
        relation_name = rel_name
        relation_name = rel_name.gsub(/@/, "_at_") if rel_name.to_s.include?('@')
        if @wl_program.wlcollections.has_key? relation_name
          tuples.each do |tuple|
            if tuple.is_a? Array or tuple.is_a? Struct
              if tuple.size == @wl_program.wlcollections[relation_name].arity

                if @provenance
                  coll = tables[relation_name.to_sym]
                  if coll.is_a? BudCollection
                    begin
                      # PENDING change here for propagate_deletion
                      deleted = coll.delete_without_invalidation tuple
                      (valid[relation_name] ||= []) << deleted
                    rescue StandardError => error
                      err[[relation_name,tuple]]=error.inspect
                    end
                  end
                else
                  coll = tables[relation_name.to_sym]
                  if coll.is_a? BudTable
                    begin
                      coll.pending_delete tuple
                      (valid[relation_name] ||= []) << tuple
                    rescue StandardError => error
                      err[[relation_name,tuple]]=error.inspect
                    end
                  else
                    raise WLError, "try to delete facts from a #{coll.class} instead of a table collection"
                  end
                end
                
              else
                err[[rel_name,tuple]] = "fact of arity #{tuple.size} in relation #{k} of arity #{arity}"
              end
            else
              err[[rel_name,tuple]] = "fact in relation #{k} with value \"#{tuple}\" should be an Array or struct instead found a #{tuple.class}"
            end
          end # tuples.each
        else
          err[[rel_name,tuples]] = "relation name #{rel_name} translated to #{relation_name} has not been declared previously"
        end   
      end # facts.each_pair
      return valid, err
    end # delete_facts_in_coll
    

    # Read incoming packets on the channels and format them into an array of
    # WLPacketData
    #
    # @return [Array] array of WLPacketData
    #
    def read_packet_channel
      return chan.read_channel(@options[:debug])
    end

    # Create the static rule from a seed previously evaluated.  Bind all
    # possible variables of a seed template with value found in intermediary
    # relation.
    def make_seed_sprout
      new_rules = {}
      # for each seeds entry
      @seed_to_sprout.each do |sts|
        bud_coll_name = sts[4]
        coll = @tables[bud_coll_name.to_sym]
        template = @wl_program.parse sts[2]
        new_rule = nil
        var_to_bound = template.body.first.variables[2]
        # FIXME instead of each tuple iterate over the delta of new tuples would
        # be better for each tuple in intermediary relation
        coll.pro do |tuple|
          new_rule = String.new template.show_wdl_format
          var_to_bound.each_index do |ind_var|
            # FIXME hard coded @ to add quotes around field value but not around
            # relation name and peer name
            new_rule = new_rule.gsub "#{var_to_bound[ind_var]}@", "#{tuple[ind_var]}@"
            new_rule = new_rule.gsub "@#{var_to_bound[ind_var]}", "@#{tuple[ind_var]}"
            new_rule = new_rule.gsub "#{var_to_bound[ind_var]}", "#{tuple[ind_var]}"
          end
          # add new rules only if it has not already been derived
          unless @sprout_rules.has_key?(new_rule)
            new_rules[new_rule] = new_rule
          end
        end
      end
      return new_rules
    end

    # This method aggregates all the fact, rules and declarations of each peer
    # in a single packet for this peer. This method allow to be sure that facts
    # and rules deduce at the same timestep will be received in the remote peer
    # at the same timestep.
    #
    # FIXME optimization this fact aggregation is a useless overhead that can be
    # avoid if I create as many sbuffer collection as non-local relation in head
    # of rules.
    def write_packet_on_channel
      packets_to_send = []
      facts_to_send = aggregate_facts(sbuffer)
      peer_to_contact = Set.new(facts_to_send.keys)
      peer_to_contact.merge(@rules_to_delegate.keys)
      if @options[:wl_test]
        @wl_callback.each_value do |callback|
          if callback[0] == :callback_step_write_on_chan
            block = callback[1]
            unless block.respond_to?(:call)
              raise WLErrorCallback,
                "Trying to call a callback method that is not responding to call #{block}"
            end
            block.call(self, facts_to_send, peer_to_contact)
          end
        end
      end
      peer_to_contact.each do |dest|
        packet = WLPacket.new(dest, @peername, @budtime)
        packet.data.facts = facts_to_send[dest]
        packet.data.rules = @rules_to_delegate[dest]
        packet.data.declarations = @relation_to_declare[dest]
        packets_to_send << packet.serialize_for_channel
      end
      if @options[:wl_test]
        @test_send_on_chan = Marshal.load(Marshal.dump(packets_to_send))
        @wl_callback.each_value do |callback|
          if callback[0] == :callback_step_write_on_chan_2
            block = callback[1]
            raise WLErrorCallback, "Trying to call a callback method that is not responding to call #{block}" unless block.respond_to?(:call)
            block.call(self, packets_to_send)
          end
        end
      end
      packets_to_send.each do |packet|
        chan <~ [packet]
      end
      # TODO: improvement relation_to_declare and rules_to_delegate could be
      # emptied only when a ack message is received from remote peers to be sure
      # that rules and relations have been correctly installed.
      #
      # job done clean the list of pending delegations and relations to send
      @relation_to_declare.clear
      @rules_to_delegate.clear

      if @options[:debug]
        puts "BEGIN display what I wrote in chan to be send"
        wlpacketsdata = chan.pending
        puts "number of packets: #{wlpacketsdata.size}"
        wlpacketsdata.keys.each do |packet|
          puts "Received from #{packet.first}"
          if packet[1].nil?
            puts "empty packet from #{packet.first}"
          else
            data = packet[1]
            wlpacketdata = WLPacketData.new data[0], data[1], data[2]
            wlpacketdata.pretty_print
          end
        end
        puts "END"
      end
    end

    public

    # Register a callback triggered during the tick at the moment specified by
    # *step*, it will execute &blk
    #
    # Note that option :wl_test must be set for the wlbud instance otherwise
    # callback are ignored. This callback are used for test and must not be used
    # for production.
    #
    # * :callback_step_received_on_chan called in the tick just after inbound
    #   has been flushed into chan
    # * :callback_step_write_on_chan, :callback_step_write_on_chan_2 two
    #   callback called just after writing on channel
    # * :callback_step_end_tick is called at the end of the tick with self as
    #   argument
    #
    # === return
    # the callback id useful to unregister the callback later
    #
    def register_wl_callback(step, &blk)
      unless @wl_callback_step.include? step
        raise WLBud::WLErrorCallback, "no such callback step #{step}"
      end
      if @wl_callback.has_key? @wl_callback_id
        raise WLBud::WLErrorCallback, "callback duplicate key"
      end
      @wl_callback[@wl_callback_id] = [step, blk]
      cb_id = @wl_callback_id
      @wl_callback_id += 1
      return cb_id
    end

    # Unregister the callback by id given during registration
    #
    def unregister_wl_callback(cb_id)
      raise WLBud::WLErrorCallback, "missing callback: #{cb_id.inspect}" unless @wl_callback.has_key? cb_id
      @wl_callback.delete(cb_id)
    end

    # Create if needed the directory for the rules if rule_dir does not exists
    # or is not writable.
    #
    # @return [String] the name of dir where rule files will be stored
    #
    def create_rule_dir(rule_dir)
      base_dir = WL::get_path_to_rule_dir
      Dir.mkdir(base_dir) unless (File::directory?(base_dir))
      returned_dir = rule_dir || "wlrdir_#{@peername}_#{Time.now}_#{self.class}_#{@peername.object_id}"
      returned_dir = File.join(base_dir,WLTools.friendly_filename(returned_dir))
      if File.writable?(base_dir)
        Dir.mkdir(returned_dir) unless (File::directory?(returned_dir))
      else
        raise WLError, "Right to write needed in the rule directory of webdamlog"
      end # unless File.directory?(rule_dir)
      return returned_dir
    end # create_rule_dir

    # Clear the content of the rule dir for this peer
    def clear_rule_dir
      unless @rule_dir.nil?
        Dir.foreach(@rule_dir) do |filename|
          file_to_delete = File.join(@rule_dir, filename)
          File.delete(file_to_delete) if File.file?(file_to_delete)
        end
        Dir.rmdir(@rule_dir)
        return true
      else
        # silent quit
        return false
      end
    end

    # a default path to create a rule dir
    def self.get_path_to_rule_dir
      base_dir = File.expand_path(File.dirname(__FILE__))
      return File.join(base_dir, RULE_DIR_NAME)
    end
  end # class WL

  # Build a packet to write on the channel with all the standard meta-data. It
  #   is recommended to use this method to generate packet of standard format.
  #
  # ==== Attributes
  #
  # * +dest+ - IP of the peer on which to send the data
  # * +facts+ - list of facts order by relations
  # * +delegations+ - rules to delegate
  # * +declarations+ - new relations to declare (must correspond to one of the
  #   relations used in the delegations of this package).
  #
  # ==== Examples
  #
  #    none
  #
  def packet_builder(dest,facts,delegations,declarations)
    Packet.new(dest, @peername, @budtime, nil)
  end

  # This method group facts by relations and by peers.
  #
  # ==== return a hash
  #
  # * +key+ destination
  # * +value+ hash of relation with their facts
  def aggregate_facts(fact_buffer)
    sto = fact_buffer.pro{ |t| t.to_a }
    facts_by_peer = WLTools::merge_multivaluehash_grouped_by_field(sto,0)
    facts_by_peer_and_relations = {}
    facts_by_peer.each_pair do |k, v|
      facts_by_peer_and_relations[k] = WLTools::merge_multivaluehash_grouped_by_field(v,0)
    end
    return facts_by_peer_and_relations
  end

  def pretty_string(print_table)
    s1 = print_table[0].to_s + "\t"
    s2 = print_table[1].inspect + "\t"
    s3 = print_table[2].to_s
    return s1 + s2 + s3
  end

  # This method formats a fact table to be processed by WebdamExchange manager
  # module.
  #
  def fact_we_output(print_table)
    s1 = print_table[0].to_s
    s2 = print_table[1].inspect
    s3 = print_table[2].to_s
    s1.strip!;s2.strip!;s3.strip!
    return "[fact]:" + s1 + ":"+ s2 + ":" + s3
  end
end