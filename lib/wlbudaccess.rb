require_relative 'wlbud'

module WLBudAccess
  extend WLBud

  PATH_LIB = File.expand_path(File.dirname(__FILE__))
  PATH_WLBUDACCESS = File.expand_path("wlbudaccess/", PATH_LIB)

  # create omega for access control computations
  require "#{PATH_WLBUDACCESS}/wlaccess"
  require 'polyglot'
  require 'treetop'
  require "#{PATH_LIB}/wlbudoverride"
  require "#{PATH_LIB}/wlbudoverride/wlagrammar"

  class WLA < WLBud::WL

    def make_bud_program
      super

      if @options[:accessc]
        # #apply policies
        @wl_program.wlpolicies.each {|p| apply_policy(p)}
        @extended_collections_to_flush.each {|col|
          @wl_program.wlcollections[col.fullrelname] = col
        }
        # #Until this implementation can have variables for a peer name, have to
        # do this manually
        if @options[:optim1] && @options[:send_writeable]
          str_res = ""
          @wl_program.wlpeers.each {|p|
            if p[0] != @peername
              str_res << "sbuffer <= acl_at_#{@peername} {|rel| [\"#{p[1]}\",
              \"writeable_at_#{p[0]}\", [\"#{peername}\", rel.rel]] if
              rel.priv == \"W\" && rel.plist.include?(\"#{p[0]}\")};"
            end
          }
          puts "Installing bud rule #{str_res}" if @options[:debug]
          optim1name = "webdamlog_#{@peername}_writeable"
          filestr = build_string_rule_to_include(optim1name, str_res)
          fullfilename = File.join(@rule_dir, optim1name)
          fout = File.new("#{fullfilename}", "w+")
          fout.puts "#{filestr}"
          fout.close
          load fullfilename
        end
      end
    end

    def translate_rule(wlrule)
      raise "Impossible to add in bud a rule that is either unbound or non-local" unless @wl_program.bound_n_local?(wlrule)
      puts "Adding a rule: #{wlrule}" if @options[:debug]
      @wl_program.disamb_peername!(wlrule)
      rule = "#{@wl_program.translate_rule_str(wlrule)}"
      name = "webdamlog_#{@peername}_#{wlrule.rule_id}"

      # this is a bit hacky - with access control we generate 2 rules instead of
      # one for grant priv and one for read
      if @options[:accessc]
        rule2 = "#{rule}"
        rule2.gsub! "\"R\"", "\"G\""
        rule << rule2
      end

      install_bud_rule rule, name
      @rule_installed << wlrule
      # the last element is the bud name for the block created
      return wlrule.rule_id, wlrule.show_wdl_format, "__bloom__#{name}"
    end

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

      #Need to update kind relation
      if @options[:accessc] && collection.peername == @peername
        name = collection.atom_name
        tables["t_kind".to_sym] <+ [[name, collection.get_type.to_s, collection.arity]]	  
        tables["acl_at_#{peername}".to_sym] << [name,"G", PList.new(["#{peername}"].to_set)]
        tables["acl_at_#{peername}".to_sym] << [name,"W", PList.new(["#{peername}"].to_set)]
        tables["acl_at_#{peername}".to_sym] << [name,"R", PList.new(["#{peername}"].to_set)]
        if @options[:optim2] && !collection.rel_type.intermediary?
          tables["aclf_at_#{peername}".to_sym] << [name, "R", "#{peername}_#{@formulas[@next_formula]}"]
          tables["aclf_at_#{peername}".to_sym] << [name, "G", "#{peername}_#{@formulas[@next_formula+1]}"]
          tables["formulas_at_#{peername}".to_sym] << ["#{peername}_#{@formulas[@next_formula]}", PList.new(["#{peername}"].to_set)]
          tables["formulas_at_#{peername}".to_sym] << ["#{peername}_#{@formulas[@next_formula+1]}", PList.new(["#{peername}"].to_set)]
          @next_formula+=2
        end
        #   #need to add extended collection
        extended_collection = @wl_program.parse(collection.make_extended)
        puts "Adding a collection for AC: \n #{extended_collection.show_wdl_format}" if @options[:debug]
        name, schema = self.schema_init(extended_collection)
        @extended_collections_to_flush << extended_collection

      else
        name, schema = self.schema_init(collection)
      end #accessc

      @collection_added = true
      return name.to_s, schema
    end

    # Takes in a string representing a WLRule,
    #  * parses it
    #  * rewrite it
    #  * adds its local part to the engine
    #
    # @raise [WLError] if something goes wrong @return [Array] rule_id, rule
    # string of the local rule installed or nil if the rule is fully delegated.
    def add_rule(wlpg_rule, sourcep=@peername)
      # parse
      wlrule = @wl_program.parse(wlpg_rule, true)
      wlrule.author = sourcep
      raise WLErrorProgram, "parse rule and get #{wlrule.class}" unless wlrule.is_a?(WLBud::WLRule)

      # rewrite and add it to the engine
      install_rule wlrule
    end    

    #   This is for special collections acl and kind VZM access control
    def add_aclkind
      keys=[]
      values=[]
      if @options[:accessc]
        keys << :"rel"
        keys << :"priv"
        values << :"plist"
        aclschema = {keys => values}
        self.table("acl_at_#{peername}".to_sym, aclschema)
        keys = []
        keys << :"rel"
        values = []
        values << :"kind"
        values << :"arity"
        kindschema = {keys => values}
        self.table(:t_kind, kindschema)

        tables["acl_at_#{peername}".to_sym] << ["acl_at_#{peername}", "G", PList.new(["#{peername}"].to_set)]
        tables["acl_at_#{peername}".to_sym] << ["acl_at_#{peername}", "W", PList.new(["#{peername}"].to_set)]
        tables["acl_at_#{peername}".to_sym] << ["acl_at_#{peername}", "R", PList.new(["#{peername}"].to_set)]
      end
    end

    def add_access_optim
      if @options[:accessc] and @options[:optim1]
        keys=[]
        values=[]
        keys << :"peer"
        keys << :"rel"
        writeableschema = {keys => values}
        self.table("writeable_at_#{peername}".to_sym, writeableschema)
        #FIXME! writeable distributed manually but there should be a better way to distribute 
      end

      if @options[:accessc] and @options[:optim2]
        self.table("formulas_at_#{peername}".to_sym, {[:id] => [:plist]})
        self.table("aclf_at_#{peername}".to_sym, [:rel,:priv] => [:formula])
        self.table("extended_formulas_at_#{peername}".to_sym, [:formula] => [:symbol,:plist])
        self.table("symbols_at_#{peername}".to_sym, [:plist] => [:symbol])

        tables["formulas_at_#{peername}".to_sym] <+ [[Omega.instance.to_s, Omega.instance]]
        tables["extended_formulas_at_#{@peername}".to_sym] <+ [[Omega.instance.to_s, Omega.instance,Omega.instance]]
      end
    end

    #   Takes in an access policy and updates acl
    def apply_policy(policy)
      puts "Applying access policy #{policy.show}" if @options[:debug]
      #   #TODO - need to give automatic read/write for a peer who has grant
      #   priv
      priv = policy.access_type.to_s
      rel = policy.relname + "_at_" + self.peername
      peer = policy.access.value

      #   #support special case of peer list from a relation
      if policy.access.relation?
        #   #have to make a string to pass into bloom to evaluate
        str_res = "acl_at_#{self.peername} <= #{policy.access.fullrelname} {|t| [\"#{rel}\",'#{priv}',t[0]]};"
        #   #write to a file
        policyname = "webdamlog_#{@peername}_policy_#{priv}_#{rel}_#{policy.access.relname}"
        filestr = build_string_rule_to_include(policyname, str_res)
        fullfilename = File.join(@rule_dir, policyname)
        fout = File.new("#{fullfilename}", "w+")
        fout.puts "#{filestr}"
        fout.close
        load fullfilename
      elsif policy.access.all?
        tables["acl_at_#{self.peername}".to_sym] << [rel,priv,Omega.instance]
        if @options[:optim2] && priv != "W"
          form = tables["aclf_at_#{self.peername}".to_sym][[rel,priv]].formula
          tables["formulas_at_#{self.peername}".to_sym] << [form,Omega.instance]
        end
      else
        tables["acl_at_#{self.peername}".to_sym] << [rel,priv,PList.new([peer].to_set)]
        if @options[:optim2] && priv != "W"
          form = tables["aclf_at_#{self.peername}".to_sym][[rel,priv]].formula
          tables["formulas_at_#{self.peername}".to_sym] << [form, PList.new([peer].to_set)]
        end
      end
    end

    def install_rule wlrule
      puts "installing rule #{wlrule} whose author is #{wlrule.author}" if @options[:debug]
      if @wl_program.bound_n_local?(wlrule) && (!@options[:accessc] || !@wl_program.nonlocalheadrules.include?(wlrule) || @options[:optim1])
        return translate_rule(wlrule)
      else # rewrite
        return rewrite_rule(wlrule)        
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
        facts.each {|wlf| 
          if wlf.fullrelname.eql?(wlcollection.atom_name)
            if @options[:accessc]
              #need to add two facts for each one
              fct = wlf.content
              fct.unshift("R")
              fct.push("Omega.instance")
              tbl << fct
              fct2 = fct.clone
              fct2.shift
              fct2.unshift("G");
              tbl << fct2
            else
              tbl << wlf.content
            end
          end
        }
        str << "#{@wl_program.make_rel_name(wlcollection.fullrelname)} <= "
        if @options[:accessc]
          str << tbl.inspect.gsub("\"Omega.instance\"", "Omega.instance")
        else
          str << tbl.inspect
        end
        str << ";\n"
      }
      str << "}"
      block = eval("Proc.new" + str)
      # #this is the same as what is done in bootstrap method in monkeypatch.rb
      meth_name = "__bootstrap__#{self.class.to_s}".to_sym
      self.class.send(:define_method, meth_name, block)
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
    # For access control we turn psets from arrays (which they were for sending
    # back into proper lattice objects
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
                  # access control need to change plist arrays back to sets
                  if @options[:accessc]
                    tuple.collect! {|x|
                      if x.is_a?(Array)
                        if (x.include?("All peers"))
                          Omega.instance
                        else
                          PList.new(x.to_set)
                        end
                      elsif (x.is_a?(String) && x.start_with?(":form:"))
                        FormulaList.make_new(x[6..-1])
                      else
                        x
                      end
                    }
                    if !relation_name.include? "_plus_at_"
                      #can only insert into extended relations
                      relation_name = @wl_program.make_rel_name(relation_name)
                      #add 2 tuples, one for G, one for R
                      tuple.push(Omega.instance)
                      secondtuple = tuple.clone
                      tuple.unshift("R")
                      secondtuple.unshift("G")
                      tables[relation_name.to_sym] <+ [secondtuple]
                    end
                  end
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
        elsif @options[:accessc] && @options[:optim1] && relation_name.start_with?("writeable")
          puts "Updating #{relation_name} with #{tuples}" if @options[:debug]
          tuples.each do |tuple|
            if tuple.is_a? Array or tuple.is_a? Struct
              begin
                tables[relation_name.to_sym] <+ [tuple]
                (valid[relation_name] ||= []) << tuple
              rescue StandardError => error
                err[[k,tuple]]=error.inspect
              end
            else
              err[[k,tuple]] = "fact in relation #{k} with value \"#{tuple}\" should be an Array or struct instead found a #{tuple.class}"
            end
          end # tuples.each do |tuple|
          @acl_updated = true
        elsif @options[:accessc] && @options[:optim2] && relation_name.start_with?("formulas")
          tuples.each do |tuple|
            if tuple.is_a? Array or tuple.is_a? Struct
              begin
                tuple.collect! {|x|
                  if x.is_a? Array
                    if x.include?("All peers")
                      Omega.instance
                    else
                      PList.new(x.to_set)
                    end
                  else
                    x
                  end
                }
                puts "updating #{relation_name} with #{tuple}" if @options[:debug]
                tables[relation_name.to_sym] << tuple
                (valid[relation_name] ||= []) << tuple
              rescue StandardError => error
                err[[k,tuple]]=error.inspect
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
            #for access control need to increment index by 1 because of priv being always first
            tuple_var = ind_var
            if @options[:accessc]
              tuple_var+=1
            end
            # FIXME hard coded @ to add quotes around field value but not around
            # relation name and peer name
            new_rule = new_rule.gsub "#{var_to_bound[ind_var]}@", "#{tuple[tuple_var]}@"
            new_rule = new_rule.gsub "@#{var_to_bound[ind_var]}", "@#{tuple[tuple_var]}"
            new_rule = new_rule.gsub "#{var_to_bound[ind_var]}", "#{tuple[tuple_var]}"
          end
          # add new rules only if it has not already been derived
          unless @sprout_rules.has_key?(new_rule)
            new_rules[new_rule] = new_rule
          end
        end
      end
      return new_rules
    end

    # This method group facts by relations and by peers.
    #
    # @return [Hash] {@dest, {@peer_name, [[atom1,...], [atom2,...],... ] }}
    #
    # * +key+ destination
    # * +value+ hash of relation with their facts
    # 
    # For access control we have to replace pset lattices with arrays for sending over the wire
    def aggregate_facts(fact_buffer)
      sbuffer_facts = DeepClone.clone(super(fact_buffer))
      if @options[:accessc]
        sbuffer_facts.values.each {|fctsinr| #this is the list of collections to update for a peer
          #accumulate a set of used formulas
          formulas_used = [].to_set
          fctsinr.values.each { |fcts|
            fcts.each {|tuple| #tuple is an array
              if tuple.is_a? Array
                tuple.collect! {|x| 
                  if (x.is_a? PList)
                    x.to_a
                  elsif (x.is_a? FormulaList)
                    formulas_used.add(x)
                    ":form:" + x.to_a
                  else
                    x
                  end
                }
              end
            }
          }
          if @options[:optim2]
            #reduce the formulas to set of symbols used
            symbols_used = [].to_set
            formulas_used.each { |formula|
              symbols_used.merge(formula.to_s.split(' '))
            }
            #look up the symbols used and send them
            tmp,pr = fctsinr.keys.first.split('_at_')
            symboltups = []
            symbols_used.each { |symbol|
              if !symbol.kind_of?(Omega) #don't need to send Omega
                val = tables["formulas_at_#{peername}".to_sym][[symbol]].to_a
                symboltups << val
              end
            }
            if symboltups.length > 0
              fctsinr["formulas_at_#{pr}"] = symboltups
            end
          end
        }      
      end
      return sbuffer_facts
    end

  end #class WLBudA
    
end #module WLBudAccess
