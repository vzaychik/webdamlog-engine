# Bud methods overriden specifically access control
module WLBud
  attr_accessor :connections_buffer
  attr_accessor :connections_status

  class WL

    #FIXME - refactor to avoid full copy-and-paste from original
    def initialize (peername, pgfilename, options = {})
      # ### WLBud:Begin adding to Bud special bud parameter initialization
      if options[:measure]
        @start_time = Time.now
      end
      # Name of that peer
      @peername = peername
      # TODO check if already created it may contains previous entries to load
      # since it may be a peer that has been restarted Directory to store rules
      # in files to be parsed by bud
      @rule_dir = create_rule_dir(options[:rule_dir])
      raise WLError, "you must give or provide read and write access to a file for reading rules to provide to bud, but it seems impossible with: #{@rule_dir}" unless File.writable?(@rule_dir)
      # #debug message
      options[:debug] ||= false
      $BUD_DEBUG ||= options[:bud_debug]
      # #additional module with bud block to import
      options[:modulename] ||= nil
      WLTools::Debug_messages.h1 "Peer #{@peername} start of initialization" if options[:debug]
      @filename = pgfilename
      # This flag is set to true when the wl_program is made via the
      # make_program method. It is used to consider the delegation spawned by
      # the program evaluation.
      @first_tick_after_make_program=false
      # It represents the list of new delegations to send at this tick.
      #
      # ===Details
      # Hash where key="peer_name destination" and values are all the rules to
      # be sent to the peer in key in the wlprogam input format. Basically rules
      # can come into this Hash only from rule rewriting or come from a seed
      # rule that have new values at this tick.
      @rules_to_delegate = Hash.new{ |h,k| h[k]=Array.new }
      # It represents the list of new relation declarations to send at this
      # tick.
      #
      # !@attributes [Hash] peer address => Set:(string wlgrammar collection
      # declaration)
      # ===Details
      # New relations to declare on remote peers, these are the intermediary
      # ones appearing in one of the delegations in rules_to_delegate.
      @relation_to_declare = Hash.new{ |h,k| h[k]=Array.new }
      # if true rule received will be placed into pending_delegations instead of
      # being added
      @filter_delegations = options[:filter_delegations] ||= false
      # @!attributes [Hash] if filter_delegations is true, delegations received
      #   from other peers are put in this hash peername: timestamp: rule1 rule2
      @pending_delegations = Hash.new{ |h,k| h[k]=Hash.new{ |h2,k2| h2[k2]=Array.new } }
      # List of rules installed and currently evaluated by the engine
      @rule_installed = []
      # The list of array containing seeds to sprout in the third step. Its
      # content comes from wl_program.new_seed_rule_to_install with a new fifth
      # field that is the name of the intermediary relation in bud array
      # [seeder, interm_rel_in_rule, seedtemplate, wlrule, rel_name_in_bud]
      @seed_to_sprout = []
      # New rules generated from a seed to install
      @new_sprout_rules = {}
      # Rules generated from a seed
      @sprout_rules = {}
      # Schedule the end of the Webdamlog engine at the given tick it will dies
      # by itself
      @dies_at_tick = options[:dies_at_tick] ||= 0
      # Store the state of the relations at the previous tick (used for
      # differential computation)
      @cached_facts = {}

      if options[:wl_test]
        @test_received_on_chan = []
        @test_send_on_chan = []
        @wl_callback = {}
        @wl_callback_id = 0
        @wl_callback_step = Set[
          :callback_step_received_on_chan,
          :callback_step_write_on_chan,
          :callback_step_write_on_chan_2,
          :callback_step_end_tick ]
      end
      # ### WLBud:End adding to Bud
      options[:dump_rewrite] ||= ENV["BUD_DUMP_REWRITE"].to_i > 0
      options[:dump_ast]     ||= ENV["BUD_DUMP_AST"].to_i > 0
      options[:print_wiring] ||= ENV["BUD_PRINT_WIRING"].to_i > 0
      @qualified_name = ""
      @tables = {}
      @lattices = {}
      @channels = {}
      @dbm_tables = {}
      @zk_tables = {}
      @stratified_rules = []
      @push_elems = {}
      @callbacks = {}
      @callback_id = 0
      @shutdown_callbacks = {}
      @shutdown_callback_id = 0
      @post_shutdown_callbacks = []
      @timers = []
      @app_tables = []
      @inside_tick = false
      @tick_clock_time = nil
      @budtime = 0
      @inbound = {}
      @done_bootstrap = false
      @done_wiring = false
      @instance_id = ILLEGAL_INSTANCE_ID # Assigned when we start running
      @metrics = {}
      @endtime = nil
      @this_stratum = 0
      @push_sorted_elems = nil
      @running_async = false
      @bud_started = false

      # Setup options (named arguments), along with default values
      @options = options.clone
      @options[:ip] ||= "127.0.0.1"
      @ip = @options[:ip]
      @options[:port] ||= 0
      @options[:port] = @options[:port].to_i
      # NB: If using an ephemeral port (specified by port = 0), the actual port
      # number won't be known until we start EM

      load_lattice_defs
      builtin_state

      # VZM connections
      @connections_buffer = {}
      @connections_status = {}

      # VZM access control
      @options[:accessc] ||= false
      self.add_aclkind
      self.add_access_optim
      @extended_collections_to_flush = []
      @packet_metrics = []
      # #### WLBud:Begin adding to Bud
      #
      if @options[:measure]
        @measure_obj = WlMeasure.new @budtime, @peername, @options[:measure_file]
      end
      @need_rewrite_strata=false
      @done_rewrite={}
      @collection_added=false
      # Loads .wl file containing the setup(facts and rules) for the Webdamlog
      #   instance.
      @wl_program = WLBud::WLProgram.new(@peername, @filename, @ip, @options[:port], false, {:debug => @options[:debug], :accessc => @options[:accessc], :optim1 => @options[:optim1], :optim2 => @options[:optim2]} )
      # By default provenance is used to spread deletion, use this tag for
      #   experimental comparisons
      @options[:noprovenance] ? @provenance = false : @provenance = true
      @provenance_graph = ProvenanceGraph.new if @provenance
      
      # XXX : added comments on budlib (unofficial):
      # - wlbud => initialize
      # - bud.rb => rewrite_local_methods
      # - bud_meta.rb => rewrite_rule_block Bloom programs consists of Bloom
      #   Blocks that are interpreted as instance methods by the bud compiler
      #   with a certain format (__bloom__.+ in regex). What we do is create new
      #   such methods from our .wl file for the class and give them an
      #   appropriate name, so that Bud believes these are methods identical to
      #   his bloom do.
      unless @wl_program.empty? or @wl_program.collection_empty?
        make_bud_program
      else
        raise WLError, "the program is empty, impossible to generate corresponding facts and rules"
      end
      @first_tick_after_make_program=true
      # ### WLBud:End adding to Bud

      resolve_imports
      call_state_methods

      @viz = VizOnline.new(self) if @options[:trace]
      @rtracer = RTrace.new(self) if @options[:rtrace]

      # #WLBud:Begin alternative to Bud Contains all the code needed to build
      # dependency graph and organize it in strata for bud semi-naive
      # evaluation. Some bud legacy code plus incremental adding rule methods
      rewrite_strata
      WLTools::Debug_messages.h1 "Peer #{@peername} end of initialization" if @options[:debug]
      # ### WLBud:End alternative to Bud
    end

    #FIXME - refactor to avoid this copy-and-paste
    def tick_internal
      # ### WLBud:Begin adding to Bud
      #
      # part 1: setup
      if @options[:debug]
        puts "==================================================================\n"
        puts "\t\t\tOutput for internal tick turn #{budtime} at peer #{peername} \n"
      end
      if @options[:measure]
        @measure_obj.initialize_measures @budtime
      end
      # Send the delegation issued by the bootstrap program
      if @first_tick_after_make_program
        @relation_to_declare.merge!(@wl_program.flush_new_relations_to_declare_on_remote_peer){|key,oldv,newv| oldv += newv}
        @rules_to_delegate.merge!(@wl_program.flush_new_delegations_to_send){|key,oldv,newv| oldv += newv}
        @first_tick_after_make_program=false
        @first_tick_after_make_program.freeze
      end

      # already in bud but I moved receive_inbound before all the stuff about
      # app_tables, push_sorted_elements, ...
      receive_inbound

      # termination condition
      if @dies_at_tick > 0 and @budtime == @dies_at_tick
        # kill himself when dies_at_tick is reached
        rel_name = "peer_done_at_#{@peername}"
        if @tables[rel_name.to_sym]
          add_facts({ rel_name => [[true]] })
        else
          raise WLError, "the special table peer_done should have been declared \
to kill this peer, in a webdamlog program it is expected that you add \n \
collection int peer_done#{@peername}(key*);"
        end
      end
      # ### WLBud:End adding to Bud

      puts "#{object_id}/#{port} : ============================================= (#{@budtime})" if $BUD_DEBUG
      begin
        starttime = Time.now if @options[:metrics]
        if @options[:metrics] and not @endtime.nil?
          @metrics[:betweentickstats] ||= initialize_stats
          @metrics[:betweentickstats] = running_stats(@metrics[:betweentickstats],
            starttime - @endtime)
        end

        @inside_tick = true

        # ### WLBud:Begin adding to Bud
        
        # reset the do_extra_tick variable that is set to true by perform extra
        # tick used to start a new tick when extensional relations are updated
        # locally
        @do_extra_tick = false
        if @options[:measure]
          @measure_obj.append_measure @budtime
        end
        if @options[:wl_test]
          # callback insertion of callback_step_received_on_chan Marshalling is
          # used to deep duplicate the object
          @test_received_on_chan = Marshal.load(Marshal.dump(read_packet_channel))
          @wl_callback.each_value do |callback|
            if callback[0] == :callback_step_received_on_chan
              block = callback[1]
              if block.respond_to?(:call)
                block.call(self)
              else
                raise WLErrorCallback,
                  "Trying to call a callback method that is not responding to call #{block}"
              end
            end
          end
        end
        # add/remove facts, add new relations declaration and rules
        read_packet_channel.each do |packet_value|
          if @options[:debug]
            puts "Process packets received from #{packet_value.print_meta_data}"
          end
          delete_facts(packet_value.facts_to_delete) unless packet_value.facts_to_delete.nil?
          packet_value.declarations.each { |dec| add_collection(dec) } unless packet_value.declarations.nil?          
          # VZM
          if @options[:accessc]
            @extended_collections_to_flush.each {|col|
              @wl_program.wlcollections[col.fullrelname] = col
            }
          end
          if @options[:filter_delegations]
            @pending_delegations[packet_value.peer_name.to_sym][packet_value.src_time_stamp] << packet_value.rules
          else
            packet_value.rules.each{ |rule| add_rule(rule, packet_value.peer_name) } unless packet_value.rules.nil?
          end
          add_facts(packet_value.facts) unless packet_value.facts.nil?
        end
        # PENDING remove new_sprout_rules attribute add new rules from seeds
        @new_sprout_rules = make_seed_sprout
        @sprout_rules.merge!(@new_sprout_rules) { |key,v1,v2| raise WLError, "seed generated a duplicate" if v1 == v2 }
        @new_sprout_rules.each_key { |key| add_rule(key) }
        @new_sprout_rules.clear

        if @options[:measure]
          @measure_obj.append_measure @budtime
        end
        # ### WLBud:End adding to Bud

        unless @done_bootstrap
          do_bootstrap
          do_wiring
        else
          # ### WLBud:Begin adding to Bud
          if @need_rewrite_strata
            rewrite_strata
            @done_wiring=false
            puts "do_wiring at tick #{budtime}" if @options[:debug]
            do_wiring
            @viz = VizOnline.new(self) if @options[:trace]
            @need_rewrite_strata=false
            @collection_added=false
          elsif @collection_added # only if collections have been added and @need_rewrite_strata is false because no rules has been added
            update_app_tables
            @collection_added = false
          end
          # ### WLBud:End adding to Bud

          # inform tables and elements about beginning of tick.
          @app_tables.each {|t| t.tick}
          @default_rescan.each {|elem| elem.rescan = true}
          @default_invalidate.each {|elem|
            elem.invalidated = true
            # Call tick on tables here itself. The rest below
            elem.invalidate_cache unless elem.class <= PushElement
          }

          # The following loop invalidates additional (non-default) elements and
          # tables that depend on the run-time invalidation state of a table.
          # Loop once to set the flags.
          each_scanner do |scanner, stratum|
            if scanner.rescan
              scanner.rescan_set.each {|e| e.rescan = true}
              scanner.invalidate_set.each {|e|
                e.invalidated = true
                e.invalidate_cache unless e.class <= PushElement
              }
            end
          end

          # Loop a second time to actually call invalidate_cache.  We can't
          # merge this with the loops above because some versions of
          # invalidate_cache (e.g., join) depend on the rescan state of other
          # elements.
          @num_strata.times do |stratum|
            @push_sorted_elems[stratum].each {|e| e.invalidate_cache if e.invalidated}
          end
        end

        # ### WLBud:Begin adding to Bud
        #
        # #part 2: logic
        #
        if @options[:measure]
          @measure_obj.append_measure @budtime
        end
        # removed receive_inbound since it has been done earlier
        #  ### WLBud:End adding to Bud compute fixpoint for each stratum in order
        @stratified_rules.each_with_index do |rules,stratum|
          fixpoint = false
          first_iter = true
          until fixpoint
            @scanners[stratum].each_value {|s| s.scan(first_iter)}
            fixpoint = true
            first_iter = false
            # flush any tuples in the pipes
            @push_sorted_elems[stratum].each {|p| p.flush}
            # tick deltas on any merge targets and look for more deltas check to
            # see if any joins saw a delta
            @push_joins[stratum].each do |p|
              if p.found_delta
                fixpoint = false
                p.tick_deltas
              end
            end
            @merge_targets[stratum].each do |t|
              fixpoint = false if t.tick_deltas
            end
          end

          # push end-of-fixpoint
          @push_sorted_elems[stratum].each do |p|
            p.stratum_end
          end
          @merge_targets[stratum].each do |t|
            t.flush_deltas
          end
        end
        @viz.do_cards(true) if @options[:trace]

        # part 3: transition
        #
        # WLBud:Begin adding to Bud
        if @options[:measure]
          @measure_obj.append_measure @budtime
        end
        # display the content of dbm
        if @options[:debug] and @options[:trace]
          puts "-----see viz logtab dbm-----"
          # #logtab = @viz.class.send(:logtab) #dbm = logtab.class.send(:dbm)
          logtab = @viz.instance_eval{ @logtab }
          # #dbm = logtab.instance_eval{ @dbm } #dbm.each{ |o| puts "#{o.class}
          # : #{o}" } #logtab.each_storage{ |s| puts s }
          logtab.to_a.sort_by{ |t| [t[0],t[1]] }.each{|s| puts s}
          # #logtab.to_a.sort{ |t1,t2| [t1[0],t1[1]] <=> [t2[0],t2[1]]
          # }.each{|s| puts s} # same result as above
          puts "----end of viz logtab-----"
        end
        # There is the moment in the tick where I should fill the channel with
        # my own structure that is the facts, the delegated rules along with the
        # newly created relations (declaration of new collections)
        write_packet_on_channel
        if @options[:measure]
          @measure_obj.append_measure @budtime
        end
        # WLBud:End adding to Bud

        do_flush

        invoke_callbacks
        @budtime += 1
        @inbound.clear
        @reset_list.each { |e| e.invalidated = false; e.rescan = false }

      ensure
        @inside_tick = false
        @tick_clock_time = nil
      end

      if @options[:wl_test]
        @wl_callback.each_value do |callback|
          if callback[0] == :callback_step_end_tick
            block = callback[1]
            unless block.respond_to?(:call)
              raise WLErrorCallback,
                "Trying to call a callback method that is not responding to call #{block}"
            end
            block.call(self)
          end
        end
      end

      if @options[:metrics]
        @endtime = Time.now
        @metrics[:tickstats] ||= initialize_stats
        @metrics[:tickstats] = running_stats(@metrics[:tickstats], @endtime - starttime)
      end
      if @options[:measure]
        @measure_obj.append_measure @budtime-1
        # count number of tuples in user tables
        tuplecount = 0;
        wordcount = 0;
        utables = @tables.keys - @builtin_tables.keys
        utables.each do |tbl|
          tuplecount += tables[tbl].length
          tables[tbl].each { |fct|
            fct.each { |elem|
              if elem.is_a? PList
                wordcount += elem.to_a.length
              else
                wordcount += 1
              end
            }
          }
        end
        @measure_obj.append_counts(@budtime-1, tuplecount, wordcount, @packet_metrics)
        @measure_obj.dump_measures      
      end

      # This peer dies if the tick finished is the last one
      peer_done_rel_name = "peer_done_at_#{@peername}"
      if @dies_at_tick > 0 and @budtime-1 == @dies_at_tick
        #want to stop but want to give the done message a chance to reach the other peers
        #FIXME - this is a hack, need a better way
        EventMachine.run {
          EventMachine.add_timer(10) { stop }
        }
        #if @tables[peer_done_rel_name.to_sym].first.key == :kill
          # Bud.shutdown_all_instances
          # Bud.stop_em_loop
        #end
      elsif @dies_at_tick == 0
        unless @tables[peer_done_rel_name.to_sym].nil?
          if @tables[peer_done_rel_name.to_sym].length > 0
            stop
            #if @tables[peer_done_rel_name.to_sym].first.key == :kill
              # Bud.shutdown_all_instances
              # Bud.stop_em_loop
            #end
          end
        end
      end      
    end

    def dies_at_tick= num
      @dies_at_tick = num
    end

  end #class

end #module
