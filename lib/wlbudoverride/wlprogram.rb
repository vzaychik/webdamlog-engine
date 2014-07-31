module WLBud

  class WLProgram
    alias_method :orig_initialize, :initialize
    alias_method :orig_translate_rule_str, :translate_rule_str

    attr_accessor :nonlocalheadrules

    def initialize (peername, filename, ip, port, make_binary_rules=false, options={})
      # List of access control policies in the program file
      # Array: (WLBud::WLPolicy)
      @wlpolicies=[]
      # === data struct
      # Array:(WLBud:WLRule) The list of rules which have a non-local head -
      # this only matters
      #  in access control on mode
      @nonlocalheadrules=[]
      orig_initialize(peername, filename, ip, port, make_binary_rules, options)
    end

    public

    # Parses one line of WLcode and adds it to the proper WL collection if the
    # add_to_program boolean is true.
    #
    # @return a WLVocabulary object corresponding to the object representation
    # of the instruction
    #
    # Rule and facts and collections are disambiguate that is local and me
    # keywords are changed into username
    #
    def parse(line, add_to_program=false, options={})
      raise WLErrorTyping, "I could only parse string not #{line.class}" unless line.is_a?(String)
      unless (output=@parser.parse(line))
        line_nb = options[:line_nb] ||= "unknown"
        raise WLErrorGrammarParsing, <<-MSG
Failure reason: #{@parser.failure_reason}
line in the file:#{line_nb}
line in the rule #{@parser.failure_line}
column:#{@parser.failure_column}
In the string: #{line}
        MSG
      else
        result = output.get_inst
        if result.is_a? WLBud::NamedSentence
          result.map_peername! { |i| WLTools.sanitize!(i) }
          disamb_peername!(result)
        end
        if add_to_program
          case result
          when WLBud::WLPeerDec
            pname = WLTools.sanitize(result.peername)
            ip = WLTools.sanitize(result.ip)
            port = WLTools.sanitize(result.port)
            add_peer pname, ip, port
          when WLBud::WLCollection
            @wlcollections[(WLTools.sanitize!(result.atom_name))] = result
          when WLBud::WLFact
            disamb_fields!(result)
            @wlfacts << result
          when WLBud::WLRule
            result.rule_id = rule_id_generator
            # assign current peer as the rule author by default
            result.author = @peername
            @rule_mapping[result.rule_id] << result
            # VZM access control - need to do additional special processing if
            # the head is not local but the body is local, then need to rewrite
            # to delegate since we need to check write permissions
            if @options[:accessc] && !@options[:optim1] && !bound_n_local?(result.head) && !result.head.relname.start_with?("deleg_") && bound_n_local?(result)
              @nonlocalheadrules << result
            end
          when WLBud::WLPolicy
            @wlpolicies << result
          end
        end
      end
      return result
    end

    # The whole rewrite process to compile Webdamlog into bud + delegation and
    # seeds. If the rule needs to be split it will create a new intermediary
    # relation that is accessible with flush_new_local_declaration. Then the
    # rule could be a simple rewriting or a seed. According to the case it will
    # populate array accessible respectively by
    # flush_new_rewritten_local_rule_to_install and
    # flush_new_seed_rule_to_install
    def rewrite_rule wlrule
      raise WLErrorTyping, "rewrite_rule accepts only WLBud::WLRule but received #{wlrule.class}" unless wlrule.kind_of?(WLBud::WLRule)
      raise WLErrorProgram, "local peername:#{@peername} is not defined yet while rewrite rule:#{wlrule}" if @peername.nil?
      split_rule wlrule
      if wlrule.seed
        rewrite_unbound_rules(wlrule)
      elsif wlrule.split
        rewrite_non_local(wlrule)
      elsif @nonlocalheadrules.include?(wlrule)
        puts "rule #{wlrule} is nonlocalhead, rewriting" if @options[:debug]
        rewrite_non_local_head_rule(wlrule)
      end
    end

    private

    # This method creates a body-local rule with destination peer p and a fully
    # non-local rule that should be delegated to p.
    #
    # === Remark
    # The intermediary relation created to link the delegated rule with the
    # rewritten local is automatically added
    #
    # This method should be called by rewrite_rule only
    #
    # RULE REWRITING If local atoms are present at the beginning of the non
    # local rule, then we have to add a local rule to the program. Otherwise,
    # the nonlocal rule can be sent as is to its destination. Create a relation
    # for intermediary relation that has the arity corresponding to the number
    # of distinct variables present in the bound atoms.
    #
    # ===return [do not use prefer the instance variable @new_local_declaration]
    # +intermediary_relation_declaration_for_local_peer+ if it exists that is
    # when splitting the rule has been necessary. That is the relation
    # declaration that should be created into bud to store intermediary local
    # results of non-local rules rewritten
    def rewrite_non_local wlrule
      raise WLErrorProgram, "trying to rewrite a seed instead of a static rule" if wlrule.seed
      
      split_rule wlrule
      if wlrule.unbound.empty?
        raise WLErrorProgram, "rewrite_non_local : You are trying to rewrite a local rule. There may be an error in your rule filter"
      else
        # The destination peer is the peer of the first nonlocal atom.
        destination_peer = wlrule.unbound.first.peername
        unless wlrule.head.variable?
          if @wlpeers[destination_peer].nil?
            raise WLErrorProgram, "In #{wlrule.unbound.first.text_value} peer is unknown it should have been declared: #{destination_peer}"
          end
        end
        addr_destination_peer = @wlpeers[destination_peer]

        if wlrule.bound.empty? # the whole body is non-local, no rewriting are needed just delegate all the rule
          delegation = wlrule.show_wdl_format

        else # if the rule must be cut in two part
          interm_relname = generate_intermediary_relation_name(wlrule.rule_id)
          interm_rel_decla, local_rule_delegate_facts, interm_rel_in_rule = wlrule.create_intermediary_relation_from_bound_atoms(interm_relname, destination_peer)
          interm_rel_declaration_for_remote_peer = "collection inter persistent #{interm_rel_decla};"
          interm_rel_declaration_for_local_peer = interm_rel_declaration_for_remote_peer.gsub("persistent ", "")
          
          # Declare the new remote relation as a scratch for the local peer and
          # add it to the program
          @new_local_declaration << parse(interm_rel_declaration_for_local_peer,true)
          @new_relations_to_declare_on_remote_peer[addr_destination_peer] << interm_rel_declaration_for_remote_peer
          # Add local rule to the set of rewritten local rules
          @new_rewritten_local_rule_to_install << ru = parse(local_rule_delegate_facts, true)
          ru.author = wlrule.author
          @rule_mapping[wlrule.rule_id] << ru.rule_id
          @rule_mapping[ru.rule_id] << ru
          # Create the delegation rule string
          nonlocalbody="" ;
          wlrule.unbound.each { |atom| nonlocalbody << "#{atom}," } ; nonlocalbody.slice!(-1)
          delegation="rule #{wlrule.head}:-#{interm_rel_in_rule},#{nonlocalbody};"
        end # if not wlrule.bound.empty? and not wlrule.unbound.empty? # if the rule must be cut in two part

        # Register the delegation
        @new_delegations_to_send[addr_destination_peer] << delegation
        @rule_mapping[wlrule.rule_id] << delegation
        @rule_mapping[delegation] << delegation
      end # if wlrule.unbound.empty?
    end # def rewrite_non_local(wlrule)

    # For access control rewrite a local rule with non-local head to have an
    #  intermediary nonlocal head plus a delegated rule to the other peer
    def rewrite_non_local_head_rule wlrule
      raise WLErrorProgram, "local peername:#{@peername} is not defined yet while rewrite rule:#{wlrule}" if @peername.nil?
      raise WLErrorProgram, "trying to rewrite the remote head rule for a local-head rule" if bound_n_local?(wlrule.head)
      
      intermediary_relation_declaration_for_remote_peer = nil
      destination_peer = wlrule.head.peername
      addr_destination_peer = @wlpeers[destination_peer]
      
      relation_name = generate_intermediary_relation_name(wlrule.rule_id)
      local_vars=[]
      wlrule.head.variables.flatten.each { |var|
        local_vars << var unless var.nil? or local_vars.include?(var)
      }
      dec_fields=''
      var_fields=''
      local_vars.each_index do |i|
        local_var=local_vars[i]
        dec_fields << local_var.gsub( /(^\$)(.*)/ , relation_name+"_\\2_"+i.to_s+"\*," )
        var_fields << local_var << ","
      end ; dec_fields.slice!(-1);var_fields.slice!(-1);

      intermediary_relation_declaration_for_remote_peer = "collection inter persistent #{relation_name}@#{destination_peer}(#{dec_fields});"
      interm_rel_declaration_for_local_peer = intermediary_relation_declaration_for_remote_peer.gsub("persistent ", "")
      @new_local_declaration << parse(interm_rel_declaration_for_local_peer,true)
      @new_relations_to_declare_on_remote_peer[addr_destination_peer] << intermediary_relation_declaration_for_remote_peer

      intermediary_relation_atom_in_rule = "#{relation_name}@#{destination_peer}(#{var_fields})"
      delegation = "rule #{wlrule.head} :- #{intermediary_relation_atom_in_rule};"
      @new_delegations_to_send[addr_destination_peer] << delegation
      @rule_mapping[wlrule.rule_id] << delegation
      @rule_mapping[delegation] << delegation
      
      rulestr = wlrule.show_wdl_format
      rulestr.gsub!('_at_','@')
      rulestr.gsub!(wlrule.head.relname, relation_name)
      @new_rewritten_local_rule_to_install << ru = parse(rulestr, true, true)
      ru.author = wlrule.author
      @rule_mapping[wlrule.rule_id] << ru.rule_id
      @rule_mapping[ru.rule_id] << ru
    end

    public

    # Generates the string representing the rule in the Bud format from a
    # WLRule
    def translate_rule_str(wlrule)
      unless wlrule.is_a?(WLBud::WLRule)
        raise WLErrorTyping,
          "wlrule should be of type WLBud::WLRule, not #{wlrule.class}"
      end
      unless (head_atom_peername = wlrule.head.peername)
        raise WLErrorGrammarParsing,
          "In this rule: #{wlrule.show}\n Problem: the name of the peer in the relation in the head cannot be extracted. Relation in the head #{wlrule.head.text_value}"
      end
      if @wlpeers[head_atom_peername].nil?
        raise WLErrorPeerId,
          "In #{wlrule.text_value} the peer name: #{head_atom_peername} cannot be found in the list of known peer: #{@wlpeers.inspect}"
      end

      if @options[:optim1]
        translate_rule_optim1(wlrule)
      elsif @options[:optim2]
        translate_rule_optim2(wlrule)
      elsif @options[:accessc]
        translate_rule_accessc(wlrule)
      else
        orig_translate_rule_str(wlrule)
      end
    end

    def translate_capc_str(wlrule)
      unless wlrule.is_a?(WLBud::WLRule)
        raise WLErrorTyping,
          "wlrule should be of type WLBud::WLRule, not #{wlrule.class}"
      end
      unless (head_atom_peername = wlrule.head.peername)
        raise WLErrorGrammarParsing,
          "In this rule: #{wlrule.show}\n Problem: the name of the peer in the relation in the head cannot be extracted. Relation in the head #{wlrule.head.text_value}"
      end
      if @wlpeers[head_atom_peername].nil?
        raise WLErrorPeerId,
          "In #{wlrule.text_value} the peer name: #{head_atom_peername} cannot be found in the list of known peer: #{@wlpeers.inspect}"
      end

      capc_str = ""
      head_str = ""
      body_str = ""

      wlrule.make_dictionaries unless wlrule.dic_made

      if !wlrule.body.empty?
        headpr = []
        noninterm = []
        wlrule.body.each_with_index do |atom, index|
          if bound_n_local?(atom) && !intermediary?(atom)
            if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
              headpr << index
            end
            noninterm << index
          end
        end
              
        if noninterm.length > 1
          noninterm.each do |index|
            if headpr.include?(index)
              capc_str << "capc_#{wlrule.rule_id}_#{wlrule.body[index].relname}_at_#{@peername} <= acl_at_#{@peername} {|t| [t.priv, t.plist] if t.rel == \"#{wlrule.body[index].fullrelname}\" && t.priv != \"W\" && t.plist.include?(\"#{wlrule.head.peername}\")};"
            else
              capc_str << "capc_#{wlrule.rule_id}_#{wlrule.body[index].relname}_at_#{@peername} <= acl_at_#{@peername} {|t| [\"G\", t.plist] if t.rel == \"#{wlrule.body[index].fullrelname}\" && t.priv == \"G\" && t.plist.include?(\"#{wlrule.author}\")};"
            end
          end

          # If there are no nongrant, i.e. non-hide atoms, then just add omega
          # grant and read
          if headpr.empty?
            capc_str << "capc_#{wlrule.rule_id}__at_#{@peername} <= "
            capc_str << "(" if noninterm > 1
            wlrule.body.each do |atom|
              if bound_n_local?(atom) && !intermediary?(atom)
                capc_str << "capc_#{wlrule.rule_id}_#{atom.relname}_at_#{@peername} * "
              end
            end
            capc_str.slice!(-3..-1)
            capc_str << ").combos" if noninterm > 1
            capc_str << " {|"
            noninterm.times do |count|
              capc_str << "capc#{count},"
            end
            capc_str.slice!(-2..-1)
            capc_str << "| [\"G\",Omega.instance]};"

            capc_str << "capc_#{wlrule.rule_id}__at_#{@peername} <= ("
            capc_str << "(" if noninterm > 1
            wlrule.body.each do |atom|
              if bound_n_local?(atom) && !intermediary?(atom)
                capc_str << "capc_#{wlrule.rule_id}_#{atom.relname}_at_#{@peername} * "
              end
            end
            capc_str.slice!(-3..-1)
            capc_str << ").combos" if noninterm > 1
            capc_str << " {|"
            noninterm.times do |count|
              capc_str << "capc#{count},"
            end
            capc_str.slice!(-2..-1)
            capc_str << "| [\"R\",Omega.instance]};"
          else
            capc_str << "capc_#{wlrule.rule_id}__at_#{@peername} <= ("
            noninterm.each do |index|
              capc_str << "capc_#{wlrule.rule_id}_#{wlrule.body[index].relname}_at_#{@peername} * "
            end
            capc_str.slice!(-3..-1)
            capc_str << ").combos"
            # natural join
            if headpr.length > 1
              capc_str << "("
              headpr.each do |index|
                capc_str << "capc_#{wlrule.rule_id}_#{wlrule.body[index].relname}_at_#{@peername}.priv => capc_#{wlrule.rule_id}_#{wlrule.body[headpr.first].relname}_at_#{@peername}.priv, " if index > 0
              end
              capc_str.slice!(-2..-1)
              capc_str << ")"
            end
            capc_str << " {|"
            noninterm.times do |count|
              capc_str << "capc#{count}, "
            end
            capc_str.slice!(-2..-1)
            capc_str << "| [capc0.priv, Omega.instance"
            noninterm.times do |index|
              capc_str << ".intersect(capc#{index}.plist)"
            end
            capc_str << "]};"
          end
        else
          atom = wlrule.body[noninterm.first]
          if headpr.include?(noninterm.first)
            capc_str << "capc_#{wlrule.rule_id}__at_#{@peername} <= acl_at_#{@peername} {|t| [t.priv, t.plist] if t.rel == \"#{atom.fullrelname}\" && t.priv != \"W\" && t.plist.include?(\"#{wlrule.head.peername}\")};"
          else
            capc_str << "capc_#{wlrule.rule_id}__at_#{@peername} <= acl_at_#{@peername} {|t| [\"G\", t.plist] if t.rel == \"#{atom.fullrelname}\" && t.priv == \"G\" && t.plist.include?(\"#{wlrule.author}\")};"
          end
        end
      end
      
      return capc_str
    end

    private

    def translate_rule_accessc(wlrule)
      str_res = ""
      body = wlrule.body

      # Generate rule head Send fact buffer if non-local head
      unless bound_n_local?(wlrule.head)
        str_res << "sbuffer <= "
      else if is_tmp?(wlrule.head)
          str_res << "temp :#{wlrule.head.fullrelname} <= "
        else
          str_res << "#{make_rel_name(wlrule.head.fullrelname)} <= "
        end
      end

      # Make the locations dictionaries for this rule
      wlrule.make_dictionaries unless wlrule.dic_made

      if body.length==0
        # VZM:TODO! - when is rule body length ever 0??? and what do we do in
        #  such cases with access controL?
        puts "translation of rule with zero body length while in access control mode not implemented!!!"
      else
        s = make_combos(wlrule)
        str_res << s

        str_res << " {|";
        wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}, "}
        str_res.slice!(-2..-1) #remove last and before last

        # VZM access control - need to add variable names for each acl we added
        wlrule.body.each do |atom|
          if bound_n_local?(atom) && !intermediary?(atom)
            str_res << ", #{atom.relname}acl"
          end
        end
        if (bound_n_local?(wlrule.head) && wlrule.author != @peername)
          str_res << ", aclw"
        end

        str_res << "| "
        
        str_res << projection_bud_string(wlrule)
        str_res << condition_bud_string(wlrule)

        # add the check for the right plist in acls #add the check that we can
        # write to the head relation
        if str_res.include?(" if ")
          str_res << " && "
        else
          str_res << " if "
        end
        # select just the Read tuples
        wlrule.body.each do |atom|
          if bound_n_local?(atom) && !intermediary?(atom)
            if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
              str_res << "#{atom.relname}acl.rel == \"#{atom.fullrelname}\" && #{atom.relname}acl.priv == \"R\" && "
            elsif (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
                (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
              str_res << "#{atom.relname}acl.rel == \"#{atom.fullrelname}\" && #{atom.relname}acl.priv == \"G\" && "
            end
          end
        end
        wlrule.body.each do |atom|
          str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.priv == \"R\" && "
        end
        
        # check for read or grant for target peer on preserved relations only
        first_intersection = true
        wlrule.body.each do |atom|
          if bound_n_local?(atom) && !intermediary?(atom)
            if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
              str_res << "("
              str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              unless first_intersection
                str_res << ")"
              end
              str_res << ".intersect"
              str_res << "(#{atom.relname}acl.plist).intersect"
              first_intersection = false
            end
          end
        end
        
        unless first_intersection
          str_res.slice!(-10..-1)
          str_res << ").include?(\"#{wlrule.head.peername}\") && "
        end

        # check for grant for author peer on hide relations only
        first_intersection = true
        wlrule.body.each do |atom|
          if bound_n_local?(atom) && !intermediary?(atom)
            if (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
                (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
              str_res << "("
              str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              unless first_intersection
                str_res << ")"
              end
              str_res << ".intersect"
              if bound_n_local?(atom) && !intermediary?(atom)
                str_res << "(#{atom.relname}acl.plist).intersect"
              end
              first_intersection = false
            end
          end
        end
          
        if first_intersection
          str_res.slice!(-3..-1)
        else
          str_res.slice!(-10..-1)
          str_res << ").include?(\"#{wlrule.author}\")"
        end

        puts "rule head is not local " if !bound_n_local?(wlrule.head) if @options[:debug]
        puts "rule author is #{wlrule.author}, peername is #{@peername}" if @options[:debug]
        if wlrule.author != @peername && bound_n_local?(wlrule.head)
          str_res << " && aclw.priv == \"W\" && aclw.rel == \"#{wlrule.head.fullrelname}\" && aclw.plist.include?(\"#{wlrule.author}\")"
        end
        
        str_res << "};"
      end
    end

    def translate_rule_optim1(wlrule)
      str_res = ""
      body = wlrule.body

      # Generate rule head Send fact buffer if non-local head
      unless bound_n_local?(wlrule.head)
        str_res << "sbuffer <= "
      else if is_tmp?(wlrule.head)
          str_res << "temp :#{wlrule.head.fullrelname} <= "
        else
          str_res << "#{make_rel_name(wlrule.head.fullrelname)} <= "
        end
      end
      
      # Make the locations dictionaries for this rule
      wlrule.make_dictionaries unless wlrule.dic_made
      
      if body.length==0
        # VZM:TODO! - when is rule body length ever 0??? and what do we do in
        # such cases with access controL?
        puts "translation of rule with zero body length while in access control mode not implemented!!!"
      else
        str_res << "("
        wlrule.body.each do |atom|
          str_res << "rext_#{wlrule.rule_id}_#{atom.relname}_at_#{@peername} * "
        end
        # TODO - probably need to do a push selection on writeable as well
        # because of cartesian product
        if !bound_n_local?(wlrule.head) && wlrule.author == @peername
          str_res << "writeable_at_#{@peername} * "
        end
        str_res << "capc_#{wlrule.rule_id}__at_#{@peername}).combos("
        
        # create join conditions
        combos=false
        wlrule.dic_wlvar.each do |key,value|
          next unless value.length > 1 # skip free variable (that is occurring only once in the body)
          next if key == '$_' # skip anonymous variable PENDING parsing string directly here is subject to bugs in general create good data structure
          
          v1 = value.first
          rel_first , attr_first = v1.split('.')
          # join every first occurrence of a variable with its subsequent
          value[1..-1].each do |v|
            rel_other , attr_other = v.split('.')
            rel_first_name = wlrule.dic_invert_relation_name[Integer(rel_first)]
            rel_other_name = wlrule.dic_invert_relation_name[Integer(rel_other)]
            first_atom = wlrule.body[Integer(rel_first)]
            other_atom = wlrule.body[Integer(rel_other)]
            col_name_first = get_column_name_of_relation(first_atom, Integer(attr_first))
            col_name_other = get_column_name_of_relation(other_atom, Integer(attr_other))
            # If it is a self-join symbolic name should be used
            if rel_first_name.eql?(rel_other_name)
              # if_str << " && #{wlrule.dic_relation_name[rel_first]}.#{attr_first}==#{wlrule.dic_budvar[rel_other]}.#{attr_other}"
              str_res << ":#{col_name_first}" << ' => ' << ":#{col_name_other}"
              combos = true
            else
              str_res << "rext_#{wlrule.rule_id}_#{rel_first_name}." << col_name_first << ' => ' << "rext_#{wlrule.rule_id}_#{rel_other_name}." << col_name_other
              combos = true
            end
            str_res << ','
          end
        end

        # natural join on priv
        wlrule.body.each do |atom|
          if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
              (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
            str_res << "capc_#{wlrule.rule_id}__at_#{@peername}.priv => rext_#{wlrule.rule_id}_#{atom.relname}_at_#{@peername}.priv, "
            combos = true
          end
        end
        str_res.slice!(-2..-1) if combos #remove last and before last
        str_res << ") {|"

        wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}, "}

        if (!bound_n_local?(wlrule.head) && wlrule.author == @peername)
          str_res << "aclw, "
        end
        str_res << "capc"
        
        str_res << "| "
        
        str_res << projection_bud_string(wlrule)
        str_res << condition_bud_string(wlrule)

        puts "rule head is not local " if !bound_n_local?(wlrule.head) if @options[:debug]
        puts "rule author is #{wlrule.author}, peername is #{@peername}" if @options[:debug]
        if !bound_n_local?(wlrule.head) && wlrule.author == @peername
          # We need to check write on the final relation, not on intermediary
          if intermediary?(wlrule.head)
            headrule = nil
            @rule_mapping.keys.each {|id|
              headrule = @rule_mapping[id]
              break if headrule.include?(wlrule.rule_id)
            }
            if !bound_n_local?(headrule.first.head)
              if str_res.include?(" if ")
                str_res << " && "
              else
                str_res << " if "
              end
              str_res << "aclw.rel == \"#{headrule.first.head.fullrelname}\" && aclw.peer == \"#{headrule.first.head.peername}\""
            end
          else
            if str_res.include?(" if ")
              str_res << " && "
            else
              str_res << " if "
            end

            str_res << "aclw.rel == \"#{wlrule.head.fullrelname}\" && aclw.peer == \"#{wlrule.head.peername}\""
          end
        end
      
        str_res << "};"
      end

      # make selections over body relations since bud doesn't do push selections
      wlrule.body.each do |atom|
        if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
            (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
          str_res << "rext_#{wlrule.rule_id}_#{atom.relname}_at_#{@peername} <= #{make_rel_name(atom.fullrelname)} {|t| t if t.plist.include?(\"#{wlrule.head.peername}\")};"
        elsif (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
            (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
          str_res << "rext_#{wlrule.rule_id}_#{atom.relname}_at_#{@peername} <= #{make_rel_name(atom.fullrelname)} {|t| t if t.plist.include?(\"#{wlrule.author}\") && t.priv == \"G\"};"
          str_res << "rext_#{wlrule.rule_id}_#{atom.relname}_at_#{@peername} <= #{make_rel_name(atom.fullrelname)} {|t| ["
          # add the list of variable and constant that should be projected
          str_res << "\"R\", "
          fields = wlcollections[atom.fullrelname].fields
          fields.each do |f|
            str_res << "t.#{f}, "
          end
          str_res << "t.plist] if t.plist.include?(\"#{wlrule.author}\") && t.priv == \"G\"};"
        end
      end

      return str_res
    end

    def translate_rule_optim2(wlrule)
      str_res = ""
      body = wlrule.body

      # Generate rule head Send fact buffer if non-local head
      unless bound_n_local?(wlrule.head)
        str_res << "sbuffer <= "
      else if is_tmp?(wlrule.head)
          str_res << "temp :#{wlrule.head.fullrelname} <= "
        else
          str_res << "#{make_rel_name(wlrule.head.fullrelname)} <= "
        end
      end

      # Make the locations dictionaries for this rule
      wlrule.make_dictionaries unless wlrule.dic_made

      if body.length==0
        if @options[:accessc]
          # VZM:TODO! - when is rule body length ever 0??? and what do we do in
          # such cases with access controL?
          puts "translation of rule with zero body length while in access control mode not implemented!!!"
        end

        str_res << " ["
        str_res << projection_bud_string(wlrule)
        str_res << "];"
      else
        if body.length==1 && !@options[:accessc]
          str_res << body.first.fullrelname
        else
          s = make_combos(wlrule)
          str_res << s
        end
        str_res << " {|";
        wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}, "}
        str_res.slice!(-2..-1) #remove last and before last

        # VZM access control - need to add variable names for each acl we added
        if @options[:accessc]
          wlrule.body.each do |atom|
            if bound_n_local?(atom) && !intermediary?(atom)
              if !@options[:optim1]
                str_res << ", #{atom.relname}acl"
              end
            end
          end
          if @options[:optim1]
            str_res << ", capchead, capcbody"
          end
          if @options[:optim2]
            str_res << ", formul"
          end
          if (bound_n_local?(wlrule.head) && wlrule.author != @peername && !@options[:optim1]) ||
              (@options[:optim1] && !bound_n_local?(wlrule.head) && wlrule.author == @peername)
            str_res << ", aclw"
          end
        end

        str_res << "| "
        
        str_res << projection_bud_string(wlrule)
        str_res << condition_bud_string(wlrule)

        # add the check for the right plist in acls #add the check that we can
        # write to the head relation
        if @options[:accessc]
          if str_res.include?(" if ")
            str_res << " && "
          else
            str_res << " if "
          end
          # select just the Read tuples #str_res << "atom0.priv == \"Read\" &&
          # "
          wlrule.body.each do |atom|
            if bound_n_local?(atom) && !intermediary?(atom)
              if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                  (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
                if !@options[:optim1]
                  str_res << "#{atom.relname}acl.rel == \"#{atom.fullrelname}\" && #{atom.relname}acl.priv == \"R\" && "
                end
              elsif (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
                  (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
                if !@options[:optim1]
                  str_res << "#{atom.relname}acl.rel == \"#{atom.fullrelname}\" && #{atom.relname}acl.priv == \"G\" && "
                end
              end
            end
          end
          wlrule.body.each do |atom|
            str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.priv == \"R\" && "
          end

          # check for read or grant for target peer on preserved relations
          # only
          first_intersection = true
          wlrule.body.each do |atom|
            if bound_n_local?(atom) && !intermediary?(atom)
              if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                  (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
                str_res << "("
                str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
                unless first_intersection
                  str_res << ")"
                end
                str_res << ".intersect"
                if !@options[:optim1]
                  str_res << "(#{atom.relname}acl.plist).intersect"
                end
                first_intersection = false
              end
            end
          end
          
          unless first_intersection
            if @options[:optim1]
              str_res << "(capchead.plist)).include?(\"#{wlrule.head.peername}\") && capchead.priv == \"R\" && " 
            elsif @options[:optim2]
              str_res.slice!(-10..-1)
              # FIXME - need to have a special case for Omega
              str_res << ") == formul.id && formul.plist.include?(\"#{wlrule.head.peername}\" && "
            else
              str_res.slice!(-10..-1)
              str_res << ").include?(\"#{wlrule.head.peername}\") && "
            end
          end

          # check for grant for author peer on hide relations only
          first_intersection = true
          wlrule.body.each do |atom|
            if bound_n_local?(atom) && !intermediary?(atom)
              if (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
                  (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
                str_res << "("
                str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
                unless first_intersection
                  str_res << ")"
                end
                str_res << ".intersect"
                if bound_n_local?(atom) && !intermediary?(atom) && !@options[:optim1]
                  str_res << "(#{atom.relname}acl.plist).intersect"
                end
                first_intersection = false
              end
            end
          end
          
          if first_intersection
            str_res.slice!(-3..-1)
          else
            if @options[:optim1]
              str_res << "(capcbody.plist)).include?(\"#{wlrule.author}\") && capcbody.priv == \"body\" "
            else
              str_res.slice!(-10..-1)
              str_res << ").include?(\"#{wlrule.author}\")"
            end
          end

          puts "rule head is not local " if !bound_n_local?(wlrule.head) if @options[:debug]
          puts "rule author is #{wlrule.author}, peername is #{@peername}" if @options[:debug]
          if wlrule.author != @peername && bound_n_local?(wlrule.head) && !@options[:optim1]
            str_res << " && aclw.priv == \"W\" && aclw.rel == \"#{wlrule.head.fullrelname}\" && aclw.plist.include?(\"#{wlrule.author}\")"
          elsif @options[:optim1] && !bound_n_local?(wlrule.head) && wlrule.author == @peername
            # Ee need to check write on the final relation, not on intermediary
            if intermediary?(wlrule.head)
              headrule = nil
              @rule_mapping.keys.each {|id|
                headrule = @rule_mapping[id]
                break if headrule.include?(wlrule.rule_id)
              }
              if !bound_n_local?(headrule.first.head)
                str_res << " && aclw.rel == \"#{headrule.first.head.fullrelname}\" && aclw.peer == \"#{headrule.first.head.peername}\""
              end
            else
              str_res << " && aclw.rel == \"#{wlrule.head.fullrelname}\" && aclw.peer == \"#{wlrule.head.peername}\""
            end
          end
        end
        
        str_res << "};"
      end
    end

    def translate_formula_str(wlrule)
      unless wlrule.is_a?(WLBud::WLRule)
        raise WLErrorTyping,
          "wlrule should be of type WLBud::WLRule, not #{wlrule.class}"
      end
      unless (head_atom_peername = wlrule.head.peername)
        raise WLErrorGrammarParsing,
          "In this rule: #{wlrule.show}\n Problem: the name of the peer in the relation in the head cannot be extracted. Relation in the head #{wlrule.head.text_value}"
      end
      if @wlpeers[head_atom_peername].nil?
        raise WLErrorPeerId,
          "In #{wlrule.text_value} the peer name: #{head_atom_peername} cannot be found in the list of known peer: #{@wlpeers.inspect}"
      end

      formula_str = ""
      wlrule.make_dictionaries unless wlrule.dic_made

      if @options[:optim2] && !wlrule.body.empty?
        # go through the intersections that are required and add them to the
        # formulas relation
        intersects = []
        wlrule.body.each do |atom|
          if bound_n_local?(atom) && !intermediary?(atom)
            if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
              intersects << atom.fullrelname
            end
          end
        end
        unless intersects.empty?
          # FIXME - make work for more than 2 relations. however, this is
          # limited by bud's self-join limit
          rel1 = intersects.pop
          rel2 = intersects.pop
          # FIXME - how do we handle Omega?
          if rel2.nil?
            formula_str << "formulas_at_#{peername} <= (formulas_at_#{peername}*formulas_at_#{peername}*formulas2_at_#{peername}*formulas2_at_#{peername}*#{rel1}*aclf_at_#{peername}*#{rel2}*aclf_at_#{peername}).combos {|f1,f2,f3,f4,r1,acl1,r2,acl2| [f1.id+\"*\"+f2.id+\"*\"+f3.id+\"*\"+f4.id,f1.plist.intersect(f2.plist).intersect(f3.plist).intersect(f4.plist)] if f1.id == r1.plist && f2.id == acl1.plist && f3.id == r2.plist && f4.id == acl2.plist && acl1.rel == \"#{rel1}\" && acl2.rel == \"#{rel2}\"};"
          else
            formula_str << "formulas_at_#{peername} <= (formulas_at_#{peername}*formulas_at_#{peername}*#{rel1}*aclf_at_#{peername}).combos {|f1,f2,r1,acl1| [f1.id+\"*\"+f2.id,f1.plist.intersect(f2.plist)] if f1.id == r1.plist && f2.id == acl1.plist && acl1.rel == \"#{rel1}\"};"
          end
        end
      end

      return formula_str
    end

    # Generates the string representing the relation name If access control is
    # on, turns into extended relation unless it's a delegated relation
    def make_rel_name (rel)
      rel, pname = rel.split('_at_')
      str_res = "#{rel}"

      if @options[:accessc]
        str_res << "_plus"
      end

      str_res << "_at_#{pname}"
      return str_res
    end

    # According to the variable found in the head of the rule this method define
    #   the schema of tuples to produce from the variable appearing in the body.
    #
    # For a bud rule like the following it produce the part between stars marked
    # with ** around
    #
    # !{descendant_at_emilien <= child_at_emilien {|atom0| *[atom0[0],
    # atom0[2]]*}
    def projection_bud_string (wlrule)
      str = '['

      # add the remote peer and relation name which should receive the fact.
      #   conform to facts to be sent via sbuffer
      unless bound_n_local?(wlrule.head)
        destination = "#{@wlpeers[wlrule.head.peername]}"
        # add location specifier
        raise WLErrorPeerId, "impossible to define the peer that should receive a message" if destination.nil? or destination.empty?
        str << "\"#{destination}\", "
        relation = "#{make_rel_name(wlrule.head.fullrelname)}"
        raise WLErrorProgram, "impossible to define the relation that should receive a message" if destination.nil? or destination.empty?
        str << "\"#{relation}\", "
        str << "["
      end

      if @options[:accessc]
        #add privilege
        if @options[:optim1]          
          str << "atom0.priv, "        
        else          
          str << "\"R\", "        
        end        
      end

      # add the list of variable and constant that should be projected
      fields = wlrule.head.fields
      fields.each do |field|
        textfield = field.token_text_value
        if field.variable?
          if wlrule.dic_wlvar.has_key?(textfield)
            relation , attribute = wlrule.dic_wlvar.fetch(textfield).first.split('.')
            if @options[:accessc]
              #priv is the first element in all extended collections with access control
              #thus have to adjust all by 1
              attribute = attribute.to_i + 1
            end
            str << "#{WLBud::WLProgram.atom_iterator_by_pos(relation)}[#{attribute}], "
          else
            if field.anonymous?
              raise(WLErrorGrammarParsing,
                "Anonymous variable in the head not allowed in " + wlrule.text_value)
            else
              raise(WLErrorGrammarParsing,
                "In rule "+wlrule.text_value+" #{textfield} is present in the head but not in the body. This is not WebdamLog syntax.")
            end
          end
        else
          str << "#{WLTools::quote_string(textfield)}, "
        end
      end

      if @options[:accessc]        
        #add plist computation        
        str << "Omega.instance"        

        if extensional_head?(wlrule)          
          #only intersect those that have preserve on them          
          wlrule.body.each do |atom|            
            if !atom.provenance.empty? && atom.provenance.type == :Preserve              
              str << ".intersect(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist)"                            
              if bound_n_local?(atom) && !intermediary?(atom)                
                if !@options[:optim1]                  
                  str << ".intersect(#{atom.relname}acl.plist)"                
                end              
              end            
            end          
          end        
        else          
          #if there is a hide, do not carry over the access restrictions          
          wlrule.body.each do |atom|            
            if atom.provenance.empty? || atom.provenance.type != :Hide              
              str << ".intersect(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist)"              
              if bound_n_local?(atom) && !intermediary?(atom)                
                if !@options[:optim1]                  
                  str << ".intersect(#{atom.relname}acl.plist)"                
                end              
              end            
            end          
          end        
        end        
        
        if @options[:optim1] && !extensional_head?(wlrule)          
          str << ".intersect(capc.plist)"        
        end      
      else #regular non-access control execution        
        str.slice!(-2..-1) unless fields.empty?      
      end

      unless bound_n_local?(wlrule.head)
        str << "]"
      end

      str << ']'
      return str
    end

    # PENDING error in the head of the rules aren't detected during parsing but
    # here it is too late.
    #
    # Make joins when there is more than two atoms in the body. Need to call
    # make_dic before calling this function. it return the beginning of the body
    # of the bud rule containing the join of relations along with their join
    # tuple criterion for example (rel1 * rel2).combos(rel1.1 => rel2.2)
    #
    # For a bud rule like the following it produce the part between stars marked
    # with ** around
    #
    # sibling <= *(childOf*childOf).combos(:father => :father,:mother =>
    # :mother)* {|s1,s2| [s1[0],s2[0]] unless s1==s2}
    def make_combos (wlrule)
      # list all the useful relation in combo
      raise WLError, "The dictionary should have been created before calling this method" unless wlrule.dic_made
      str = '(';
      wlrule.body.each do |atom|
        str <<  "#{make_rel_name(atom.fullrelname)} * "
      end
      str.slice!(-2..-1) unless wlrule.body.empty?

      # VZM access control - need to add acls for each relation that is local
      # and not delegated
      if @options[:accessc]
        wlrule.body.each do |atom|
          if bound_n_local?(atom) && !intermediary?(atom) && !@options[:optim1]
            if @options[:optim2]
              str << " * aclf_at_#{atom.peername}"
            else
              str << " * acl_at_#{atom.peername}"
            end
          end
        end
        # instead of including acls directly, with optimization 1 we compute
        # those in a special capc relation
        if @options[:optim1]
          str << " * capc_#{wlrule.rule_id}_at_#{@peername} * capc_#{wlrule.rule_id}_at_#{@peername}"
        end
        if @options[:optim2]
          str << " * formulas_at_#{@peername}"
        end
        # in regular access control check writeable at the source prior to
        # writing with optimization 1 check only with the original rule using
        # the writeable relation and assume no malicious peers
        if wlrule.author != @peername && bound_n_local?(wlrule.head) && !@options[:optim1]
          str << " * acl_at_#{wlrule.head.peername}"
        elsif @options[:optim1] && !bound_n_local?(wlrule.head) && wlrule.author == @peername
          str << " * writeable_at_#{@peername}"
        end
      end

      str << ').combos('

      # create join conditions
      combos=false
      wlrule.dic_wlvar.each do |key,value|
        next unless value.length > 1 # skip free variable (that is occurring only once in the body)
        next if key == '$_' # skip anonymous variable PENDING parsing string directly here is subject to bugs in general create good data structure

        v1 = value.first
        rel_first , attr_first = v1.split('.')
        # join every first occurrence of a variable with its subsequent
        value[1..-1].each do |v|
          rel_other , attr_other = v.split('.')
          rel_first_name = wlrule.dic_invert_relation_name[Integer(rel_first)]
          rel_other_name = wlrule.dic_invert_relation_name[Integer(rel_other)]
          first_atom = wlrule.body[Integer(rel_first)]
          other_atom = wlrule.body[Integer(rel_other)]
          col_name_first = get_column_name_of_relation(first_atom, Integer(attr_first))
          col_name_other = get_column_name_of_relation(other_atom, Integer(attr_other))
          # If it is a self-join symbolic name should be used
          if rel_first_name.eql?(rel_other_name)            
            str << ":#{col_name_first}" << ' => ' << ":#{col_name_other}"
            combos=true
          else
            str << make_rel_name(rel_first_name) << '.' << col_name_first << ' => ' << make_rel_name(rel_other_name) << '.' << col_name_other
            combos=true
          end
          str << ','
        end
      end
      # FIXME - make the below work for more than 1 acl in the rule without it
      # clashing, if it's possible #if @options[:accessc] && !@options[:optim1]
      #  str << "acl_at_#{@peername}.priv => #{make_rel_name(wlrule.body.first.fullrelname)}.priv,"
      #  combos=true
      # end
      str.slice!(-1) if combos
      str << ')'
      
      return str
    end


  end #class
end # module
