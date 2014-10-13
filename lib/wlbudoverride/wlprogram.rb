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

      wlrule.head.fields.flatten.each { |var|
        local_vars << var.token_text_value
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

      if @options[:optim1] && @options[:optim2]
        translate_rule_optim2(wlrule)
      elsif @options[:optim1]
        translate_rule_optim1(wlrule)
      elsif @options[:optim2]
        translate_rule_optim2(wlrule)
      elsif @options[:accessc]
        translate_rule_accessc(wlrule)
      else
        orig_translate_rule_str(wlrule)
      end
    end

    # Generates the string representing the relation name If access control is
    # on, turns into extended relation unless it's a delegated relation
    def make_rel_name (rel,priv="R")
      rel, pname = rel.split('_at_')
      str_res = "#{rel}"

      if @options[:accessc]
        str_res << "_plus#{priv}"
      end

      str_res << "_at_#{pname}"
      return str_res
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
             str_res << make_rel_name(wlrule.head.fullrelname, "R")
             str_res << " <= "
           end
      end
      
      # Make the locations dictionaries for this rule
      wlrule.make_dictionaries unless wlrule.dic_made
      
      if body.length==0
        # VZM:TODO! - when is rule body length ever 0??? and what do we do in
        #  such cases with access controL?
        puts "translation of rule with zero body length while in access control mode not implemented!!!"
      else
        if body.length==1
          str_res << make_rel_name(body.first.fullrelname, "R")
        else
          s = make_combos(wlrule)
          str_res << s
        end

        str_res << " {|";
        wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}, "}
        str_res.slice!(-2..-1) #remove last and before last

        str_res << "| "

        #grab value for each relation in acl
        wlrule.body.each do |atom|
          if !intermediary?(atom)
            str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR = acl_at_#{@peername}[[\"#{atom.fullrelname}\",\"R\"]].plist;"
            str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclG = acl_at_#{@peername}[[\"#{atom.fullrelname}\",\"G\"]].plist;"
          end
          if bound_n_local?(wlrule.head)
            str_res << "aclW = acl_at_#{@peername}[[\"#{wlrule.head.fullrelname}\",\"W\"]].plist;"
          end
        end
        
        str_res << projection_bud_string(wlrule)
        str_res << condition_bud_string(wlrule)

        # add the check for the right plist in acls #add the check that we can
        # write to the head relation
        if str_res.include?(" if ")
          str_res << " && "
        else
          str_res << " if "
        end

        # check for read or grant for target peer on preserved relations only
        first_intersection = true
        wlrule.body.each do |atom|
          if bound_n_local?(atom) # && !intermediary?(atom)
            if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
              str_res << "("
              str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              unless first_intersection
                str_res << ")"
              end
              str_res << ".intersect"
              str_res << "(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR).intersect" unless intermediary?(atom)
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
          if bound_n_local?(atom) #&& !intermediary?(atom)
            if (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
                (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
              str_res << "("
              str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              unless first_intersection
                str_res << ")"
              end
              str_res << ".intersect"
              if bound_n_local?(atom) && !intermediary?(atom)
                str_res << "(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclG).intersect"
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
          str_res << " && aclW.include?(\"#{wlrule.author}\")"
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
             str_res << make_rel_name(wlrule.head.fullrelname, "R")
             str_res << " <= "
           end
      end
      
      # Make the locations dictionaries for this rule
      wlrule.make_dictionaries unless wlrule.dic_made
      
      if body.length==0
        # VZM:TODO! - when is rule body length ever 0??? and what do we do in
        # such cases with access controL?
        puts "translation of rule with zero body length while in access control mode not implemented!!!"
      else
        if body.length==1
          str_res << make_rel_name(body.first.fullrelname, "R")
        else
          str_res << make_combos(wlrule)
        end

        str_res << " {|";
        wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}, "}
        str_res.slice!(-2..-1) #remove last and before last

        str_res << "| "

        #grab value for each relation in acl
        wlrule.body.each do |atom|
          if !intermediary?(atom)
            str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR = acl_at_#{@peername}[[\"#{atom.fullrelname}\",\"R\"]].plist;"
            str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclG = acl_at_#{@peername}[[\"#{atom.fullrelname}\",\"G\"]].plist;"
          end
        end

        str_res << projection_bud_string(wlrule)
        str_res << condition_bud_string(wlrule)

        # add the check for the right plist in acls #add the check that we can
        # write to the head relation
        if str_res.include?(" if ")
          str_res << " && "
        else
          str_res << " if "
        end

        # check for read or grant for target peer on preserved relations only
        first_intersection = true
        wlrule.body.each do |atom|
          if bound_n_local?(atom) # && !intermediary?(atom)
            if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
              str_res << "("
              str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              unless first_intersection
                str_res << ")"
              end
              str_res << ".intersect"
              str_res << "(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR).intersect" unless intermediary?(atom)
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
          if bound_n_local?(atom) #&& !intermediary?(atom)
            if (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
                (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
              str_res << "("
              str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              unless first_intersection
                str_res << ")"
              end
              str_res << ".intersect"
              if bound_n_local?(atom) && !intermediary?(atom)
                str_res << "(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclG).intersect"
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
        if !bound_n_local?(wlrule.head) && wlrule.author == @peername
          # We need to check write on the final relation, not on intermediary
          if intermediary?(wlrule.head)
            headrule = nil
            @rule_mapping.keys.each {|id|
              headrule = @rule_mapping[id]
              break if headrule.include?(wlrule.rule_id)
            }
            if !bound_n_local?(headrule.first.head)
              str_res << "&& writeable_at_#{peername}[[\"#{headrule.first.head.peername}\",\"#{headrule.first.head.fullrelname}\"]]"
            end
          else
            str_res << "&& writeable_at_#{peername}[[\"#{wlrule.head.peername}\",\"#{wlrule.head.fullrelname}\"]]"

          end
        end
        
        str_res << "};"
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
             str_res << make_rel_name(wlrule.head.fullrelname, "R")
             str_res << " <= "
        end
      end

      # Make the locations dictionaries for this rule
      wlrule.make_dictionaries unless wlrule.dic_made

      if body.length==0
        # VZM:TODO! - when is rule body length ever 0??? and what do we do in
        # such cases with access controL?
        puts "translation of rule with zero body length while in access control mode not implemented!!!"
      else
        if body.length==1
          str_res << make_rel_name(body.first.fullrelname, "R")
        else
          str_res << make_combos(wlrule)
        end

        str_res << " {|";
        wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}, "}
        str_res.slice!(-2..-1) #remove last and before last

        str_res << "| "

        wlrule.body.each do |atom|
          if !intermediary?(atom)
            str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR = aclf_at_#{@peername}[[\"#{atom.fullrelname}\",\"R\"]].formula;"
            str_res << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclG = aclf_at_#{@peername}[[\"#{atom.fullrelname}\",\"G\"]].formula;"
          end
        end

        # check for read or grant for target peer on preserved relations only
        extr_def = false
        form_str = "extF = Omega.instance.intersect"

        wlrule.body.each do |atom|
          if bound_n_local?(atom)
            if (extensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Preserve) ||
                (intensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Preserve))
              form_str << "("
              form_str << "(" unless intermediary?(atom)
              form_str << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              form_str << ".intersect(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR))" unless intermediary?(atom)
              form_str << ").intersect"
              extr_def = true
            end
          end
        end

        if extr_def
          form_str.slice!(-10..-1)
          str_res << form_str
          str_res << ".to_s;"
          str_res << "extRt = extended_formulas_at_#{peername}[[extF]];"
          str_res << "if extRt then extR=extRt.plist; else "
          #compute extended formulas on demand
          str_res << "numst=[]; extF.split(' ').each {|fp| if fp == \"*\" then numst.push(numst.pop.intersect(numst.pop)) elsif fp == \"+\" then numst.push(numst.pop.merge(numst.pop)) else numst.push(formulas_at_#{peername}[[fp]].plist) end; }; newval=numst.pop; if newval.kind_of?(Omega) then newsym=Omega.instance else newsym=symbols_at_#{peername}[[newval.to_a.sort.join(\"\")]]; if newsym then newsym=newsym.symbol else newsym=\"#{peername}_\"+Time.now.nsec.to_s; symbols_at_#{peername} << [newval.to_a.sort.join(\"\"),newsym]; formulas_at_#{peername} << [newsym,newval]; end; end; extended_formulas_at_#{peername} << [extF,newsym,newval]; extR=newval; end;"
        end

        # check for grant for author peer on hide relations only
        extg_def = false
        form_str = "extF = Omega.instance.intersect"

        wlrule.body.each do |atom|
          if bound_n_local?(atom)
            if (extensional_head?(wlrule) && (atom.provenance.empty? || atom.provenance.type == :Hide)) ||
                (intensional_head?(wlrule) && !atom.provenance.empty? && atom.provenance.type == :Hide)
              form_str << "("
              form_str << "(" unless intermediary?(atom)
              form_str << "#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist"
              form_str << ".intersect(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclG))" unless intermediary?(atom)
              form_str << ").intersect"
            end
          end
        end

        if extg_def
          form_str.slice!(-10..-1)
          str_res << form_str
          str_res << ".to_s;"
          str_res << "extGt = extended_formulas_at_#{peername}[[extF]];"
          str_res << "if extGt then extG=extGt.plist else "
          #compute extended formulas on demand
          str_res << "numst=[]; extF.split(' ').each {|fp| if fp == \"*\" then numst.push(numst.pop.intersect(numst.pop)) elsif fp == \"+\" then numst.push(numst.pop.merge(numst.pop)) else numst.push(formulas_at_#{peername}[[fp]].plist) end; }; newval=numst.pop; if newval.kind_of?(Omega) then newsym=Omega.instance else newsym=symbols_at_#{peername}[[newval.to_a.sort.join(\"\")]]; if newsym.nil? then newsym=\"#{peername}_\"+Time.now.to_s; symbols_at_#{peername} << [newval.to_a.sort.join(\"\"),newsym]; formulas_at_#{peername} << [newsym,newval]; end; end; extended_formulas_at_#{peername} << [extF,newsym,newval]; extG=newval; end;"
        end

        str_res << projection_bud_string(wlrule)
        cond_str = condition_bud_string(wlrule)
        str_res << cond_str

        # add the check for the right plist in acls #add the check that we can
        # write to the head relation
        if cond_str.include?(" if ")
          str_res << " && "
        else
          str_res << " if "
        end

        str_res << "extR.include?(\"#{wlrule.head.peername}\") && " if extr_def
        str_res << "extG.include(\"\"#{wlrule.author}\") && " if extg_def 
          
        str_res.slice!(-3..-1)

        puts "rule head is not local " if !bound_n_local?(wlrule.head) if @options[:debug]
        puts "rule author is #{wlrule.author}, peername is #{@peername}" if @options[:debug]
        if @options[:optim1]
          if !bound_n_local?(wlrule.head) && wlrule.author == @peername
            # We need to check write on the final relation, not on intermediary
            if intermediary?(wlrule.head)
              headrule = nil
              @rule_mapping.keys.each {|id|
                headrule = @rule_mapping[id]
                break if headrule.include?(wlrule.rule_id)
              }
              if !bound_n_local?(headrule.first.head)
                str_res << "&& writeable_at_#{peername}[[\"#{wlrule.head.peername}\",\"#{headrule.first.head.fullrelname}\"]]"
              end
            else
              str_res << "&& writeable_at_#{peername}[[\"#{wlrule.head.peername}\",\"#{wlrule.head.fullrelname}\"]]"
            end
          end
        else
          if wlrule.author != @peername && bound_n_local?(wlrule.head)
            str_res << " && acl_at_#{wlrule.head.peername}[[\"#{wlrule.head.fullrelname}\",\"W\"]].plist.include?(\"#{wlrule.author}\")"
          end
        end

        str_res << "};"
      end
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
        relation = make_rel_name(wlrule.head.fullrelname, "R")
        raise WLErrorProgram, "impossible to define the relation that should receive a message" if destination.nil? or destination.empty?
        str << "\"#{relation}\", "
        str << "["
      end

      # add the list of variable and constant that should be projected
      fields = wlrule.head.fields
      fields.each do |field|
        textfield = field.token_text_value
        if field.variable?
          if wlrule.dic_wlvar.has_key?(textfield)
            relation , attribute = wlrule.dic_wlvar.fetch(textfield).first.split('.')
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
        if @options[:optim2]
          str << "FormulaList.make_new(extended_formulas_at_#{peername}[["
        end
        str << "Omega.instance"        

        if extensional_head?(wlrule)          
          #only intersect those that have preserve on them          
          wlrule.body.each do |atom|            
            if !atom.provenance.empty? && atom.provenance.type == :Preserve              
              str << ".intersect((#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist)"                            
              if bound_n_local?(atom) && !intermediary?(atom)
                str << ".intersect(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR))"
              else
                str << ")"
              end            
            end          
          end        
        else          
          #if there is a hide, do not carry over the access restrictions          
          wlrule.body.each do |atom|            
            if atom.provenance.empty? || atom.provenance.type != :Hide              
              str << ".intersect((#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}.plist)"              
              if bound_n_local?(atom) && !intermediary?(atom)                
                str << ".intersect(#{WLProgram.atom_iterator_by_pos(wlrule.dic_invert_relation_name.key(atom.fullrelname))}aclR))"
              else
                str << ")"
              end            
            end          
          end        
        end
        if @options[:optim2]
          str << ".to_s]].symbol)"
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

    # Define the if condition for each constant it assign its value.
    #
    # @return [String] the string to append to make the wdl rule
    def condition_bud_string wlrule
      str = ""
      first_condition = true

      # add the condition for each constant
      wlrule.dic_wlconst.each do |key,value|
        value.each do |v|
          relation_position , attribute_position = v.split('.')
          if first_condition
            str << " if "
            first_condition = false
          else
            str << " and "
          end
          str << "#{WLBud::WLProgram.atom_iterator_by_pos(relation_position)}[#{attribute_position}]==#{WLTools::quote_string(key)}"
        end
      end

      # add the condition for each self join to unfold
      wlrule.dic_wlvar.each_pair do |key,values|
        (0..values.size-2).each_with_index do |iter1,index|
          pos1 = values[iter1]
          relation_position1 , attribute_position1 = pos1.split('.')
          (index+1..values.size-1).each do |iter2|
            pos2 = values[iter2]
            relation_position2 , attribute_position2 = pos2.split('.')
            if wlrule.dic_invert_relation_name[Integer(relation_position1)] == wlrule.dic_invert_relation_name[Integer(relation_position2)]
              if first_condition
                str << " if "
                first_condition = false
              else
                str << " and "
              end
              str << "#{WLBud::WLProgram.atom_iterator_by_pos(relation_position1)}[#{attribute_position1}]==#{WLBud::WLProgram.atom_iterator_by_pos(relation_position2)}[#{attribute_position2}]"
            end
          end
        end
      end
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
      str.slice!(-1) if combos
      str << ')'
      
      return str
    end
    

  end #class
end # module
