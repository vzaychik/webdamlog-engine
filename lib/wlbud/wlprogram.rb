module WLBud

  # :title: WLProgram WLProgram is a class that parses and interprets WebdamLog
  # files (.wl). Parsing is done using the Treetop module (and wlgrammar.treetop
  # file). Interpretation is done using the three following methods. They all
  # generate an [name,proc] array used by the WLBud initializer to create an
  # instance method that would be understood as a Bloom collection by Bloom
  # engine:
  # * <tt>--generate_schema</tt> Generates relations names.
  # * <tt>--generate_bootstrap</tt> Generates extensional facts.
  # * <tt>--translate_rules</tt> Generates webdamlog rules.
  #
  # A printing function (showing information to the screen) is also avaible :
  # * <tt>--print_content</tt> print all rules, facts and relations to the
  #   screen.
  #
  class WLProgram
    attr_reader :wlcollections, :peername, :wlpeers, :wlfacts
    attr_accessor :localrules, :nonlocalrules, :delegations, :rewrittenlocal, :rule_mapping

    # The initializer for the WLBud program takes in a filename corresponding to
    # a WebdamLog file (.wl) and parses each line in the file either as a
    # relation declaration, a fact or a WebdamLog rule.
    # ==== Attributes
    #
    # * +peername+ identifier for the peer hosting this program to identify the
    #   local data
    # * +filename+ the filename containing the program (or any IO object
    #   readable)
    # * +[DEPRECATED] make_binary_rules+ false by default
    # * +options+ ...
    #
    # ==== Options
    #
    # * +:debug+ very verbose debug
    #
    # === Return
    # the list of declaration of relations to create as WLCollection object
    #
    def initialize (peername, filename, ip, port, make_binary_rules=false, options={})
      raise WLBud::WLError, 'Program file cannot be found' unless File.exist?(filename)
      # #absolute path file to the program *.wl
      @programfile = filename
      @parser = WLBud::WebdamLogGrammarParser.new
      @peername=WLTools.sanitize(peername)
      @peername.freeze
      @ip=ip
      @ip.freeze
      @port=port
      @port.freeze
      # A counter for this program to name rule with a uniq ID
      #
      @next=1
      @make_binary_rules=make_binary_rules #Use binary rule format (use Bloom pairs keyword instead of combos).
      my_address = "#{ip}:#{port}"
      # @!attribute [Hash] !{name => WLCollection} List of the webdamlog
      # relation inserted in that peer
      @wlcollections={}
      # Define here some std alias for local peer
      # * @peername
      # * 'localhost'
      # * 'me'
      #
      @localpeername = Set.new([@peername,'local','me'])
      # List of known peers
      #
      @wlpeers={}
      @wlpeers[@peername]="#{@ip}:#{@port}"
      # List of bootstrap facts ie. the facts given in the program file
      # === data struct
      # Array:(WLBud:WLFact)
      #
      @wlfacts=[]
      # The original rules before the rewriting used for evaluation. It gives
      # the original semantic of the program.
      #
      # Original rules id are stored as key and rewriting of these ones as value
      # in an array
      @rule_mapping = Hash.new{ |h,k| h[k]=Array.new }
      # The local rules straightforward to convert into bud (simple syntax
      # translation)
      # === data struct
      # Array:(WLBud:WLRule)
      #
      @localrules=[]
      # Nonlocal rules in WL are never converted into Bloom rules directly (as
      # opposed to previous types of rules). They are split in two part one
      # stored in delegation that must be send to a remote peer and another part
      # stored in rewrittenlocal that correspond to the longest sequence
      # possible to evaluate locally, that may be the whole original rule if
      # only the head was not local.
      # === data struct
      # Array:(WLBud:WLRule)
      #
      @nonlocalrules=[]
      # The list of delegation needed to send after having processed the
      # wlprogram at initialization. Ie. the non-local part of rules should
      # start with an intermediary relation that control it triggering.
      #
      # Array:(WLBud:WLRule)
      #
      @delegations = Hash.new{ |h,k| h[k]=Array.new }
      # This is the list of rules which contains the local rules after a
      # non-local rule of the wlprogram at initialization has been rewritten.
      # This kind of rule have a intermediary relation in their head that
      # control the corresponding delegated part of the rule on the remote peer.
      # === data struct
      # Array:(WLBud:WLRule)
      #
      @rewrittenlocal=[]
      # Keep the new relation to declare on remote peer (typically intermediary
      # relation created when rewrite) due to processing of of a wlgrammar line
      # in rewrite_non_local.
      # === data struct
      # Hash:(peer address, Set:(string wlgrammar collection declaration) )
      #
      @new_relations_to_declare_on_remote_peer = Hash.new{|h,k| h[k]=Set.new }
      # The list of all the new delegations to be send due to processing of a
      # wlgrammar line in rewrite_non_local. It contains the non-local part of
      # the rule that have been splitted.
      # === data struct
      # Hash:(peer address, Set:(string wlgrammar rule) )
      #
      @new_delegations_to_send = Hash.new{|h,k| h[k]=Set.new }
      # The list of all the new local collection to create due to processing of
      # a wlgrammar line in rewrite_non_local. It contains the intermediary
      # relation declaration.
      # === data struct
      # Array:(string wlgrammar collection)
      #
      @new_local_declaration = []
      # The list of all the new local rule to create due to processing of a
      # wlgrammar line in rewrite_non_local. It contains the local part of the
      # rule that have been splitted.
      # === data struct
      # Array:(WLBud::WLRule)
      #
      @new_rewritten_local_rule_to_install = []
      # #@name=@programfile.split('/').last.split('.').first
      options[:debug] ||= false
      @options=options.clone

      # Parse lines to be read
      parse_lines(IO.readlines(@programfile, ';'), true)
      # process non-local rules
      @nonlocalrules.each do |rule|
        rewrite_non_local rule
      end
    end

    public

    # The print_content method prints the content of the relations declarations,
    # extensional facts and rules of the program to the screen.
    #
    def print_content
      puts "-----------------------RELATIONS------------------------"
      @wlcollections.each_value {|wl| wl.show}
      puts "\n\n------------------------FACTS---------------------------"
      @wlfacts.each {|wl| wl.show}
      puts "\n\n------------------------RULES---------------------------"
      @localrules.each {|wl| wl.show}
      puts "\n\n--------------------------------------------------------"
    end

    # Returns true if no rules are loaded for evaluation.
    def rules_empty? ; return @rule_mapping.empty?; end

    # Returns true if no facts are loaded for evaluation.
    def facts_empty? ; return @wlfacts.empty?; end

    # Return true if no collection is loaded for evaluation.
    def collection_empty? ; return @wlcollections.empty?; end

    # Return true if the whole program to evaluate is empty
    def empty? ; return (rules_empty? and facts_empty? and collection_empty?) ; end

    def print_arg_tab(target,str)
      string=""
      target.each {|r| string << "#{r};\n"}
      puts "#{str} :{\n#{string}}"
    end

    # Parse a program. Notice that ';' is a reserved keyword for end sentence. A
    # sentence could define a peer, a collection, a fact or a rule.
    #
    # This will parse one by one the whole file until it meets a semi-colon
    #
    # @deprecated Use {IO.readlines} instead with ';' separator or customize
    # this to display nice parsing error
    #
    # ===parameter
    # * +lines+ is an array of string, each cell containing a line of the file.
    #   Usually lines is the result of IO.readlines.
    def parse_lines (lines, add_to_program=false)
      ans=[]
      current=""
      lines.each_index do |i|
        line = lines[i]
        if line =~ /;/
          splitted = line.split ';'
          current << splitted[0] << ';'
          rest = ""
          splitted[(1..-1)].each{ |r| rest << r }
          ans << parse(current, add_to_program, false, {:line_nb=>i+1})
          current = rest || "" # reset current line after parsing
        else
          current << line
        end
      end
      return ans
    end

    # Parses one line of WLcode and adds it to the proper WL collection if the
    # add_to_program boolean is true.
    #
    # @return a WLVocabulary object corresponding to the object representation
    # of the instruction
    #
    # Rule and facts and collections are disambiguate that is local and me
    # keywords are changed into username
    #
    # PENDING should check before adding rule that the all the local atoms have
    # been declared. The atoms in the head that are not local should also be
    # declared but I can also make my parser declare them automatically since
    # the type is not important.
    def parse(line, add_to_program=false, rewritten=false, options={})
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
            if rewritten
              if local?(result)
                @rewrittenlocal << result
              else
                @delegations << result
              end
            else
              @rule_mapping[result.rule_id] << result
              if local?(result)
                @localrules << result
              else
                @nonlocalrules << result
              end
            end
          end
        end
      end
      return result
    end

    # this will never override the original declaration of the current peer this
    # is to prevent changing address while running
    def add_peer(peername,ip,port)
      # PENDING add filter to sanitize IP and port
      address = "#{ip}:#{port}"
      unless @localpeername.include? peername
        @wlpeers[peername]=address
      end
      return peername, address
    end

    # This method creates a body-local rule with destination peer p and a fully
    # non-local rule that should be delegated to p.
    #
    # === Remark
    # The intermediary relation created to link the delegated rule with the
    # rewritten local is automatically added
    #
    # ===return [do not use prefer the instance variable @new_local_declaration]
    # +intermediary_relation_declaration_for_local_peer+ if it exists that is
    # when splitting the rule has been necessary. That is the relation
    # declaration that should be created into bud to store intermediary local
    # results of non-local rules rewritten
    #
    def rewrite_non_local(wlrule)  
      raise WLErrorProgram, "local peername:#{@peername} is not defined yet while rewrite rule:#{wlrule}" if @peername.nil?
      raise WLErrorProgram, "trying to rewrite a seed instead of a static rule" if wlrule.seed?

      intermediary_relation_declaration_for_local_peer = nil
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
          # FIXME hacky substitute of _at_ by @
          delegation.gsub!(/_at_/, '@')
        else # if the rule must be cut in two part
          
          # RULE REWRITING If local atoms are present at the beginning of the
          # non local rule, then we have to add a local rule to the program.
          # Otherwise, the nonlocal rule can be sent as is to its destination.
          # Create a relation for this declaration that has an arity
          # corresponding to the number of distinct variables present in the
          # local stack.
          localbody = ""
          local_vars=[]
          wlrule.bound.each do |atom|
            atom.variables.flatten.each { |var|
              local_vars << var unless var.nil? or local_vars.include?(var)
            }
            localbody << "#{atom},"
          end
          localbody.slice!(-1)
          relation_name = generate_intermediary_relation_name(wlrule.rule_id)
          # build the list of attributes for relation declaration (dec_fields)
          # removing the '$' of variable and create attributes names
          dec_fields=''
          var_fields=''
          local_vars.each_index do |i|
            local_var=local_vars[i]
            dec_fields << local_var.gsub( /(^\$)(.*)/ , relation_name+"_\\2_"+i.to_s+"\*," )
            var_fields << local_var << ","
          end ; dec_fields.slice!(-1);var_fields.slice!(-1);

          intermediary_relation_atom_in_rule = "#{relation_name}@#{destination_peer}(#{var_fields})"
          intermediary_relation_declaration_for_remote_peer = "collection inter persistent #{relation_name}@#{destination_peer}(#{dec_fields});"
          intermediary_relation_declaration_for_local_peer = intermediary_relation_declaration_for_remote_peer.gsub("persistent ", "")
          local_rule_which_delegate_facts = "rule #{intermediary_relation_atom_in_rule}:-#{localbody};"
          # #Declare the new remote relation as a scratch for the local peer and
          # add it to the program
          @new_local_declaration << parse(intermediary_relation_declaration_for_local_peer,true,true)
          @new_relations_to_declare_on_remote_peer[addr_destination_peer] << intermediary_relation_declaration_for_remote_peer
          # #Add local rule to the set of rewritten local rules
          @new_rewritten_local_rule_to_install << ru = parse(local_rule_which_delegate_facts, true, true)
          @rule_mapping[wlrule.rule_id] << ru.rule_id
          @rule_mapping[ru.rule_id] << ru
          # #Create the delegation rule string
          nonlocalbody="" ;
          wlrule.unbound.each { |atom| nonlocalbody << "#{atom}," } ; nonlocalbody.slice!(-1)
          delegation="rule #{wlrule.head}:-#{intermediary_relation_atom_in_rule},#{nonlocalbody};"
        end # if not wlrule.bound.empty? and not wlrule.unbound.empty? # if the rule must be cut in two part

        # Register the delegation
        @new_delegations_to_send[addr_destination_peer] << delegation
        @rule_mapping[wlrule.rule_id] << delegation
        @rule_mapping[delegation] << delegation
      end # if wlrule.unbound.empty?
      return intermediary_relation_declaration_for_local_peer
    end # def rewrite_non_local(wlrule)

    # Split the rule by reading atoms from left to right until non local atom or
    # variable in relation name or peer name has been found
    def split_rule wlrule
      unless wlrule.split
        to_delegate = false
        wlrule.body.each do |atom|
          if !to_delegate and local?(atom) and not atom.variable?
            wlrule.bound << atom
          else
            to_delegate=true
            wlrule.unbound << atom
          end
        end
        wlrule.split = true
      end
    end

    # Generates the string representing the rule in the Bud format from a
    # WLrule.
    #
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
      str_res = ""
      str_self_join = ""
      body = wlrule.body

      # Generate rule head Send fact buffer if non-local head
      unless local?(wlrule.head)
        str_res << "sbuffer <= "
      else if is_tmp?(wlrule.head)
          str_res << "temp :#{make_rel_name(wlrule.head.fullrelname)} <= "
        else
          str_res << "#{make_rel_name(wlrule.head.fullrelname)} <= "
        end
      end

      # #Obsolete code when self-joins where badly implemented #rename_atoms
      # adds temp relations in case of self joins. #renamed = rename_atoms(body)
      # #renamed.each {|relation| strRes <<  "#{relation};\n"} unless
      # @make_binary_rules

      # #Make the locations dictionaries for this rule
      wlrule.make_dictionaries unless wlrule.dic_made

      #      if @options[:debug] then
      #        WLTools::Debug_messages.h4("Display dictionaries generated for rule \n\t#{wlrule.to_s}\n")
      #        puts <<-END
      #          dic_wlvar - #{wlrule.dic_wlvar.inspect}
      #          dic_wlconst - #{wlrule.dic_wlconst.inspect}
      #          dic_relation_name - #{wlrule.dic_relation_name.inspect}
      #          dic_invert_relation_name - #{wlrule.dic_invert_relation_name.inspect}
      #        END
      #      end

      if body.length==0
        if @options[:accessc]
          #VZM:TODO! - when is rule body length ever 0??? and what do we do in such cases with access controL?
          puts "translation of rule with zero body length while in access control mode not implemented!!!"
        end

        str_res << " ["
        str_res << projection_bud_string(wlrule)
        str_res << "];"
      else
        if body.length==1 && !@options[:accessc]
          str_res << body.first.fullrelname
        else
          # #Generate rule collection names using pairs and combos keywords.
          #          if @make_binary_rules
          #            s , str_self_join = make_pairs(wlrule)
          #          else
          s , str_self_join = make_combos(wlrule)
          #          end
          str_res << s
        end
        str_res << " {|";
        wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}, "}
        str_res.slice!(-2..-1) #remove last and before last

        #VZM access control - need to add variable names for each acl we added
        if @options[:accessc]
          wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << ", #{WLProgram.atom_iterator_by_pos(v)}acl"}
          str_res << ", aclw"
        end

        str_res << "| "
        
        str_res << projection_bud_string(wlrule)
        str_res << condition_bud_string(wlrule)

        #add the check for the right plist in acls
        #add the check that we can write to the head relation
        if @options[:accessc]
          if str_res.include?(" if ")
            str_res << " && "
          else
            str_res << " if "
          end
          wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}acl.priv == \"Read\" && #{WLProgram.atom_iterator_by_pos(v)}acl.rel == \"#{wlrule.dic_invert_relation_name[v]}\" && "}
          str_res << "("
          wlrule.dic_invert_relation_name.keys.sort.each {|v| str_res << "#{WLProgram.atom_iterator_by_pos(v)}.plist & #{WLProgram.atom_iterator_by_pos(v)}acl.plist & "}
          str_res.slice!(-3..-1)
          str_res << ").include?(\"#{wlrule.head.peername}\")"

          str_res << " && aclw.priv == \"Write\" && aclw.rel == \"#{wlrule.head.fullrelname}\" && aclw.plist.include?(\"#{peername}\")"
        end
        
        #        unless wlrule.dic_wlconst.empty?
        #          str_res << str_self_join.sub(/&&/,'if')
        #        else
        #          str_res << str_self_join
        #        end

        str_res << "};"
      end
    end

    # Generates the string representing the relation name
    # If access control is on, turns into extended relation
    def make_rel_name (rel)
      rel, pname = rel.split('_at_')
      str_res = "#{rel}"

      if @options[:accessc]
        str_res << "_ext"
      end

      str_res << "_at_#{pname}"
      return str_res
    end

    # Read the content and erase. It return the hash of the collection to create
    # and clear it after.
    #
    # == return
    #
    # a hash with
    # * +key+  peerIp:port
    # * +value+ array with the relation as strings in wlpg format
    #
    def flush_new_relations_to_declare_on_remote_peer
      unless @new_relations_to_declare_on_remote_peer.empty?
        flush = @new_relations_to_declare_on_remote_peer.dup
        flush.each_pair { |k,v| flush[k]=v.to_a }
        @new_relations_to_declare_on_remote_peer.clear
      else
        flush={}
      end
      return flush
    end

    # Read the content and erase. It return the hash of the delegation to send
    # and clear it after.
    #
    #  == return
    #
    # a hash with
    # * +key+  peerIp:port
    # * +value+ array with the relation as strings in wlpg format
    #
    def flush_new_delegations_to_send
      unless @new_delegations_to_send.empty?
        flush = @new_delegations_to_send.dup
        flush.each_pair { |k,v| flush[k]=v.to_a }
        @new_delegations_to_send.clear
      else
        flush={}
      end
      return flush
    end

    # Read new_local_declaration content and clear it. It return the array of
    # the collections to create and clear it after.
    #
    # == return
    #
    # an array of wlgrammar collections
    #
    def flush_new_local_declaration
      unless @new_local_declaration.empty?
        flush = @new_local_declaration.dup
        @new_local_declaration.clear
      else
        flush=[]
      end
      return flush
    end

    # Read new_rewritten_local_rule_to_install content and clear it. It return
    # the array of the rules to create and clear it after.
    #
    # == return
    #
    # an array of wlgrammar rules
    #
    def flush_new_rewritten_local_rule_to_install
      unless @new_rewritten_local_rule_to_install.empty?
        flush = @new_rewritten_local_rule_to_install.dup
        @new_rewritten_local_rule_to_install.clear
      else
        flush=[]
      end
      return flush
    end

    # return true if the given wlword is local
    #
    # according to the type of wlword which should be a wlvocabulary object or a
    # string of the peername, it test if the given argument is local ie. match
    # one of the alias name specifed in @localpeername
    #
    # Note that a rule is local if the body is local whatever the state of the
    # head
    #
    def local? (wlword)
      if wlword.is_a? WLBud::WLCollection or wlword.is_a? WLBud::WLAtom
        if @localpeername.include?(wlword.peername)
          return true
        else
          return false
        end
      elsif wlword.is_a? WLBud::WLRule
        wlword.body.each { |atom|
          unless local?(atom.peername)
            return false
          end
        }
        return true
      elsif wlword.is_a? String
        if @localpeername.include?(wlword)
          true
        else
          false
        end
      else
        raise WLErrorProgram,
          "Try to determine if #{wlword} is local but it has wrong type #{wlword.class}"
      end
    end

    # Disambiguate peername, it replace alias such as local or me by the local
    # peername id. Hence subsequent call to peername will use the unique id of
    # this peer. @param [WLBud::NamedSentence] a {WLBud::NamedSentence} object
    # @return [String] the disambiguated namedSentence
    def disamb_peername! namedSentence
      if namedSentence.is_a? String
        if @localpeername.include? namedSentence
          namedSentence.replace @peername
        end
      elsif
        namedSentence.map_peername! do |pname|
          if @localpeername.include?(pname)
            @peername
          else
            pname
          end
        end
      else
        raise WLErrorTyping, "expect an object extending WLBud::NamedSentence or a string representing the name"
      end
      return namedSentence
    end

    # Disambiguate fields, it replace alias such as local or me by the local
    # peername id. Hence subsequent call to peername will use the unique id of
    # this peer.
    def disamb_fields! wlfact
      if wlfact.is_a? WLBud::WLFact
        wlfact.map_content! do |pname|
          if @localpeername.include?(pname)
            @peername
          else
            pname
          end
        end
      else
        raise WLErrorTyping, "expect an object WLFact in disamb_fields!"
      end
    end

    # return true if wlcollection is sound compared to current program already
    # running otherwise return false with error message
    def valid_collection? wlcollection
      return false, "" unless wlcollection.is_a? WLBud::WLCollection
      return false, "In #{wlcollection.text_value} peername #{wlcollection.peername} should have been declared before" unless @wlpeers[wlcollection.peername]
      return true, "collection valid"
    end

    private

    # Define the format of the name of the variable for the name of the relation
    # inside the block of the bud rules
    def self.atom_iterator_by_pos(position)
      "atom#{position}"
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
      unless local?(wlrule.head)
        destination = "#{@wlpeers[wlrule.head.peername]}"
        # #add location specifier
        raise WLErrorPeerId, "impossible to define the peer that should receive a message" if destination.nil? or destination.empty?
        str << "\"#{destination}\", "
        relation = "#{make_rel_name(wlrule.head.fullrelname)}"
        raise WLErrorProgram, "impossible to define the relation that should receive a message" if destination.nil? or destination.empty?
        str << "\"#{relation}\", "
        str << "["
      end

      # add the list of variable and constant that should be projected
      fields = wlrule.head.fields
      fields.each do |f|
        if f.variable?
          var = f.token_text_value
          if wlrule.dic_wlvar.has_key?(var)
            relation , attribute = wlrule.dic_wlvar.fetch(var).first.split('.')
            str << "#{WLBud::WLProgram.atom_iterator_by_pos(relation)}[#{attribute}], "
          else
            if var.anonymous?
              raise(WLErrorGrammarParsing,
                "Anonymous variable in the head not allowed in " + wlrule.text_value)
            else
              raise(WLErrorGrammarParsing,
                "In rule "+wlrule.text_value+" #{var} is present in the head but not in the body. This is not WebdamLog syntax.")
            end
          end
        else
          str << "#{quote_string(f.token_text_value)}, "
        end
      end

      if @options[:accessc]
        #add priv and plist computation
        str << "\"Read\", "
        wlrule.dic_invert_relation_name.keys.sort.each {|v| str << "#{WLProgram.atom_iterator_by_pos(v)}.plist & #{WLProgram.atom_iterator_by_pos(v)}acl.plist & "}
      end

      str.slice!(-2..-1) unless fields.empty?

      unless local?(wlrule.head)
        str << "]"
      end

      str << ']'
      return str
    end

    # define the if condition for each constant it assign its value return
    # [String] the string to append to make the wdl rule
    def condition_bud_string wlrule
      str = ""
      wlrule.dic_wlconst.each do |key,value|
        value.each do |v|
          relation_position , attribute_position = v.split('.')
          if wlrule.dic_wlconst.keys.first == key
            str << " if "
          else
            str << " && "
          end
          str << "#{WLBud::WLProgram.atom_iterator_by_pos(relation_position)}[#{attribute_position}]==#{quote_string(key)}"
        end
      end
      return str
    end
    
    def make_pairs (wlrule)
      str = "(#{wlrule.body.first.fullrelname} * #{wlrule.body.last.fullrelname}).pairs(" ;
      pairs=false
      wlrule.dic_wlvar.each { |key,value| next unless value.length > 1
        rel_first , attr_first =value.first.split('.')
        rel_other , attr_other =value.last.split('.')
        if wlrule.has_self_join
          str << ":#{attr_first}" << ' => ' << ":#{attr_other}" << ',' ;
        else
          str << "#{rel_first}.#{attr_first}" << ' => ' << "#{rel_other}.#{attr_other}" << ',' ;
        end
        pairs=true
      }
      str.slice!(-1) if pairs
      str << ')'
      return str , ''
    end

    # If the name of the atom start with tmp_ or temp_ it is a temporary
    # relation so return true.
    def is_tmp? (result)
      if result.is_a?(WLBud::WLAtom)
        if result.fullrelname=~/temp_/ or result.fullrelname=~/tmp_/ then return true else return false end
      else
        raise WLErrorGrammarParsing, "is_tmp? is called on non-WLAtom object, of class #{result.class}"
      end
    end

    # FIXME error in the head of the rules aren't detected during parsing but
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

      #VZM access control - need to add acls for each relation for reading and one for writing
      if @options[:accessc]
        wlrule.body.each do |atom|
          str << " * acl_at_#{atom.peername}"
        end
        str << " * acl_at_#{wlrule.head.peername}"
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
            # if_str << " && #{wlrule.dic_relation_name[rel_first]}.#{attr_first}==#{wlrule.dic_budvar[rel_other]}.#{attr_other}"
            str << ":#{col_name_first}" << ' => ' << ":#{col_name_other}"
            combos=true
          else
            # str << WLProgram.atom_iterator_by_pos(rel_first) << attr_first <<
            # '
            # => ' << WLProgram.atom_iterator_by_pos(rel_other) << attr_other <<
            # ',' ;
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

    # Get the the name specified for the column of the relation in given atom as
    # it is declared in the collection
    def get_column_name_of_relation (atom, column_number)
      wlcoll = @wlcollections["#{atom.relname}_at_#{atom.peername}"]
      unless wlcoll.nil?
        wlcoll.fields.fetch(column_number)
      else
        raise WLErrorProgram, "in get_column_name_of_relation #{atom.relname}_at_#{atom.peername} not found in wlcollections"
      end
    end

    # Add quotes around s if it is a string
    def quote_string(s)
      s.is_a?(String) ? "\'#{s}\'" : s.to_s
    end

    # Tools for WLprogram This tool function checks if a table includes an
    # object. If so, it will return its index. Otherwise it will raise a
    # WLParsing Error.
    def include_with_index (table,obj)
      raise WLBud::WLErrorGrammarParsing, "#{obj} is a lone variable" unless table.include?(obj)
      table.each_with_index {|a,i| if obj.eql?(a) then return i else next end}
    end

    # Generate a new unique relation name for intermediary relation due to
    # delegation rewritings.
    #
    # @param [Fixnum] the rule id used in @rule_mapping usually given by
    # WLRule.rule_id
    #
    def generate_intermediary_relation_name(orig_rule_id)
      return "deleg_from_#{@peername}_#{orig_rule_id}_#{@rule_mapping[orig_rule_id].size}"
    end

    # Simple successor function useful to create id for rules in this WLprogram.
    #
    def rule_id_generator
      while @rule_mapping.has_key? @next
        @next+=1
      end
      return @next
    end

  end # class WLProgram

end # module WLBud

