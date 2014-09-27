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
        if @options[:optim2]
          str_res = ""
          @wl_program.wlpeers.each {|p|
            if p[0] != @peername
              str_res << "sbuffer <= formulas_at_#{@peername} {|rel| [\"#{p[1]}\",
              \"formulas_at_#{p[0]}\", [rel.id, rel.plist]] };"
            end
          }
          puts "Installing bud rule #{str_res}" if @options[:debug]
          optim2name = "webdamlog_#{@peername}_formulas_deleg"
          filestr = build_string_rule_to_include(optim2name, str_res)
          fullfilename = File.join(@rule_dir, optim2name)
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
      if @options[:optim1] && !@options[:optim2]
        add_capcs wlrule
        add_rexts wlrule
      end

      rule = "#{@wl_program.translate_rule_str(wlrule)}"
      name = "webdamlog_#{@peername}_#{wlrule.rule_id}"

      # this is a bit hacky - with access control we generate 2 rules instead of
      # one for grant priv and one for read
      if @options[:accessc] && (!@options[:optim1] || @options[:optim2])
        rule2 = "#{rule}"
        rule2.gsub! "\"R\"", "\"G\""
        rule << rule2
      end

      rule << @wl_program.translate_capc_str(wlrule) if @options[:optim1] && !@options[:optim2]
      rule << @wl_program.translate_formula_str(wlrule) if @options[:optim2]

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
        tables["acle_at_#{peername}".to_sym] <+ [["#{peername}", "G", name],["#{peername}", "W", name],["#{peername}", "R", name]]
        if @options[:optim2] && !collection.rel_type.intermediary?
          tables["aclf_at_#{peername}".to_sym] <+ [[name, "R", "#{peername}_#{@formulas[@next_formula]}"],[name, "G", "#{peername}_#{@formulas[@next_formula+1]}"]]
          @next_formula+=2
        end
        #   #need to add extended collection
        extended_collection = @wl_program.parse(collection.make_extended)
        puts "Adding a collection for AC: \n #{extended_collection.show_wdl_format}" if @options[:debug]
        name, schema = self.schema_init(extended_collection)
        @extended_collections_to_flush << extended_collection

        if @options[:optim2] #add special formulas collection
          add_form(collection.relname)

          #select formulas used by the relation into another relation
          if collection.rel_type.intermediary?
            formula_str = "formulas_#{collection.atom_name} <= #{wl_program.make_rel_name(collection.atom_name)} {|t| [t.plist.to_s,t.priv] unless t.plist.kind_of? Omega};\n"
          else
            formula_str = "formulas_#{collection.atom_name} <= #{wl_program.make_rel_name(collection.atom_name)} {|t| ff = t.plist.intersect(aclf_at_#{peername}[[\"#{collection.atom_name}\",t.priv]].formula); [ff.to_s,t.priv] unless ff.kind_of? Omega};\n"
          end

          formula_str << "extended_formulas_at_#{peername} <= formulas_#{collection.atom_name} {|ff| numst = []; ff.formula.split(' ').each { |fp| if fp == \"*\" then numst.push(numst.pop.intersect(numst.pop)) elsif fp == \"+\" then numst.push(numst.pop.merge(numst.pop)) else numst.push(formulas_at_#{peername}[[fp]].plist) end; }; [ff.formula,numst.pop]};"

          puts "Installing rule #{formula_str}" if @options[:debug]
          filestr = build_string_rule_to_include("webdamlog_#{peername}_formulas_#{collection.relname}", formula_str)
          fullfilename = File.join(@rule_dir, "webdamlog_#{peername}_formulas_#{collection.relname}")
          fout = File.new("#{fullfilename}", "w+")
          fout.puts "#{filestr}"
          fout.close
          load fullfilename
          @need_rewrite_strata = true
        end

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
        #acl is intensional, so declared as scratch
        #it is recomputed from acle relation which has individual statements
        self.scratch("acl_at_#{peername}".to_sym, aclschema)
        #   #need some basic default facts so need a separate extentional table
        #   acle
        keys = []
        keys << :"peer"
        keys << :"priv"
        keys << :"rel"
        acleschema = {keys => values}
        self.table("acle_at_#{peername}".to_sym, acleschema)
        keys = []
        keys << :"rel"
        values = []
        values << :"kind"
        values << :"arity"
        kindschema = {keys => values}
        self.table(:t_kind, kindschema)

        #   #install default rules into acl #have to make a string to pass into
        #   bloom to evaluate
        str_res = "acl_at_#{peername} <= acle_at_#{peername}.group([:rel,:priv],accum(:peer)) {|t| [t.peer, t.priv, PList.new(t.rel)]};"
        #   #any time kind is updated because a new relation is added, need to
        #   install into acl

        #   #str_res << "acle_at_#{peername} <= t_kind {|k| [\"#{peername}\",
        #   'G', k.rel]};" #str_res << "acle_at_#{peername} <= t_kind {|k|
        #   [\"#{peername}\", 'W', k.rel]};" #str_res << "acle_at_#{peername} <=
        #   t_kind {|k| [\"#{peername}\", 'R', k.rel]};" #peer has full privs to
        #   his own acl #str_res << "acle_at_#{peername} <= [[\"#{peername}\",
        #   \"G\", \"acl_at_#{peername}\"]];" #str_res << "acle_at_#{peername}
        #   <= [[\"#{peername}\", \"W\", \"acl_at_#{peername}\"]];" #str_res <<
        #   "acle_at_#{peername} <= [[\"#{peername}\", \"R\",
        #   \"acl_at_#{peername}\"]];"
        tables["acle_at_#{peername}".to_sym] <+ [["#{peername}", "G", "acl_at_#{peername}"],["#{peername}", "W", "acl_at_#{peername}"],["#{peername}", "R", "acl_at_#{peername}"]]
        puts "Installing bud rule #{str_res}" if @options[:debug]
        #   #write to a file
        aclrulename = "webdamlog_#{@peername}_aclkind"
        filestr = build_string_rule_to_include(aclrulename, str_res)
        fullfilename = File.join(@rule_dir, aclrulename)
        fout = File.new("#{fullfilename}", "w+")
        fout.puts "#{filestr}"
        fout.close
        load fullfilename
        @need_rewrite_strata = true
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
        #   #now need to put in the rule #FIXME! - no way to write a bud rule
        #   with variable in the rule name #so at least for now just delegate to
        #   all my peers knowledge of what they can write to
      end

      if @options[:accessc] and @options[:optim2]
        keys=[]
        values=[]
        keys << :id
        values << :plist
        formschema = {keys => values}
        self.table("formulas_at_#{peername}".to_sym, formschema)
        self.scratch("extended_formulas_at_#{peername}".to_sym, {[:id] => [:plist]})

        keys=[]
        keys << :rel
        keys << :priv
        values=[]
        values << :formula
        aclschema = {keys => values}
        self.table("aclf_at_#{peername}".to_sym, aclschema)

        tables["formulas_at_#{peername}".to_sym] <+ [[Omega.instance.to_s, Omega.instance]]
        str_res = "formulas_at_#{peername} <= (acl_at_#{peername} * aclf_at_#{peername}).combos(acl_at_#{peername}.rel => aclf_at_#{peername}.rel, acl_at_#{peername}.priv => aclf_at_#{peername}.priv) {|a,b| [b.formula, a.plist]}; extended_formulas_at_#{peername} <= formulas_at_#{peername} {|t| [t.id,t.plist]};\n"

        puts "Installing bud rule #{str_res}" if @options[:debug]
        #   #write out
        formularulename = "webdamlog_#{peername}_formulas"
        filestr = build_string_rule_to_include(formularulename, str_res)
        fullfilename = File.join(@rule_dir, formularulename)
        fout = File.new("#{fullfilename}", "w+")
        fout.puts "#{filestr}"
        fout.close
        load fullfilename
      end
    end

    #   #make capc for each relation in the body of the rule
    def add_capcs(wlrule)
      if wlrule.body.length > 1
        wlrule.body.each do |atom|
          add_capc(wlrule.rule_id, atom.relname)
        end
      end

      add_capc(wlrule.rule_id)
    end
    
    def add_capc(id,atomn="")
      keys=[]
      values=[]
      keys << :"priv"
      values << :"plist"
      capcschema = {keys => values}
      self.scratch("capc_#{id}_#{atomn}_at_#{peername}".to_sym,capcschema)
    end

    def add_rexts(wlrule)
      wlrule.body.each do |atom|
        add_rext(wlrule.rule_id, atom)
      end
    end

    def add_rext(id, atom)
      keys=[]
      values=[]
      col = @wl_program.wlcollections[atom.fullrelname]
      rext = @wl_program.parse(col.make_rext(id))
      self.schema_init(rext)
    end

    def add_form(atomn)
      keys=[]
      values=[]
      keys << :"formula"
      values << :"val"
      formschema = {keys => values}
      self.table("formulas_#{atomn}_at_#{@peername}".to_sym, formschema)
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
        str_res = "acle_at_#{self.peername} <= #{policy.access.fullrelname} {|t| [t[0],'#{priv}',\"#{rel}\"]};"
        #   #write to a file
        policyname = "webdamlog_#{@peername}_policy_#{priv}_#{rel}_#{policy.access.relname}"
        filestr = build_string_rule_to_include(policyname, str_res)
        fullfilename = File.join(@rule_dir, policyname)
        fout = File.new("#{fullfilename}", "w+")
        fout.puts "#{filestr}"
        fout.close
        load fullfilename
      elsif policy.access.all?
        puts "adding to acl Omega for #{rel} for priv #{priv}" if @options[:debug]
        str_res = "acl_at_#{self.peername} <= [[\"#{rel}\",\"#{priv}\",Omega.instance]]"
        #   #write to a file
        policyname = "webdamlog_#{@peername}_policy_#{priv}_#{rel}_#{peer}"
        filestr = build_string_rule_to_include(policyname, str_res)
        fullfilename = File.join(@rule_dir, policyname)
        fout = File.new("#{fullfilename}", "w+")
        fout.puts "#{filestr}"
        fout.close
        load fullfilename
      else
        tables["acle_at_#{self.peername}".to_sym] <+ [["#{peer}","#{priv}","#{rel}"]]
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
                  # #VZM access control need to change plist arrays back to sets
                  if @options[:accessc]
                    tuple.collect! {|x|
                      if x.is_a?(Array)
                        if (x.include?("All peers"))
                          Omega.instance
                        else
                          PList.new(x.to_set)
                        end
                      elsif (x.is_a?(String) && x.start_with?(":form:"))
                        FormulaList.new(x[6..-1])
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
                tables[relation_name.to_sym] <+ [tuple]
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
        #if formulas are the only relation sent, take it out unless sent previously
        sbuffer_facts.values.each {|fctsinr| #this is the list of collections to update for a peer
          if fctsinr.keys.length == 1 && fctsinr.keys.first.start_with?("formulas_at_")
            fctsinr.delete(fctsinr.keys.first)
            #FIXME - if the formulas were sent previously, any updates should be resent even by themselves
          else
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
              #reduce the symbols sent only to those used
              fctsinr.keys.each {|rel|
                if rel.start_with?("formulas_at_")
                  formulrel = fctsinr[rel]
                  formulrel.delete_if { |tuple|
                    !symbols_used.include? tuple[0]
                  }
                end
              }
            end
          end
        }      
      end
      return sbuffer_facts
    end

  end #class WLBudA
    
end #module WLBudAccess
