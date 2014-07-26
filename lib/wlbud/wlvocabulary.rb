module WLBud

  # The WLVocabulary classes are instantiated using the Treetop parsing gem and
  # all inherit the Treetop::Runtime::SyntaxNode class. When a .wl file is
  # parsed, a tree of nodes is created, with each node (not only the leaves) are
  # assigned a proper subclass of WLVocabulary.
  class WLVocabulary < Treetop::Runtime::SyntaxNode
    public
    def to_s
      self.text_value
    end
    def get_inst
      return instruction
    end
    # only node including {WLBud::WLComment} in their ancestry are comments
    def comment?
      false
    end
  end

  # A Webdamlog sentence with a peer name in it.
  #
  # It could be a WLPeerDec, WLColletion, WLFact, or a WLAtom in this case it
  # returns a String which is the peer name. Or it could be WLRule, in this case
  # it returns an array with the list of peer name.
  module NamedSentence

    attr_accessor :peername

    # the peer name of this sentence
    def peername
      raise MethodNotImplementedError, "a WLBud::NamedSentence subclass must implement the method peername"
    end

    # Assign value returned by block on each peer name
    def map_peername! &block
      raise MethodNotImplementedError, "a WLBud::NamedSentence subclass must implement the method map_peername!"
    end

    def show_wdl_format
      raise MethodNotImplementedError, "a WLBud::NamedSentence subclass must implement the method show_wdl_format"
    end
  end

  # The WLrule class is used to store the content of parsed WLRules
  class WLRule < WLVocabulary
    include WLBud::NamedSentence

    attr_accessor :has_self_join
    attr_reader :dic_made, :dic_relation_name, :dic_invert_relation_name, :dic_wlvar, :dic_wlconst
    attr_accessor :split, :seed, :split_pos, :bound, :unbound

    # Creates a new WLRule and instantiate empty dictionaries for that rule.
    #
    # The parameters are given by WebdamLogGrammarParser the
    # Treetop::Runtime::CompiledParser
    # * input
    # * interval
    # * elements
    def initialize (a1,a2,a3)
      @dic_made = false
      # unique id of the rule for this peer
      @rule_id = nil
      @author = nil
      @body = nil
      # The dic_relation_name is a hash that defines variables included in the
      # conversion from webdamlog-formatted rule to bud-formatted rule. Its key
      # is the name of the relation of which the variable is bound to. Its value
      # correspond to the local variable position where this relation appear.
      @dic_relation_name = {}
      # Inverted dictionary corresponding to dic_relation_name ie. It maps body
      # atom position to string name of the relation
      @dic_invert_relation_name = {}
      # The wlvar dictionary is a hash that contains the position of the
      # variables of each atom of the body. It takes as key the field value of
      # the variable, e.g. '$x' and as value it's location in the following
      # format : 'relation_position.field_position' Remark: position always
      # start from 0 !@attribute [Hash] list of variables "name of variable" =>
      # ["relpos.atompos", ... ] eg. {"$_"=>["0.0", "0.1"], "$id"=>["0.2"]}
      @dic_wlvar = {}
      # The const dictionary is a hash that contains the value of the constants
      # of each atom of the body. It takes as key the field value of the
      # constant, e.g. 'a' and as value it's location in the following format :
      # 'relation_position.field_position' Remark: position always start from 0
      # !@attribute [Hash] list of constants name of variable =>
      # ["relpos.atompos", ... ]
      @dic_wlconst = {}
      # nil until WLProgram.split_rule has been called which populate @bound,
      # @unbound and set split to true if unbound atoms has been found
      @split = nil      
      # nil until WLProgram.split_rule has been called, set to true if seeds
      # variables in relation or peer names
      @seed = nil
      # nil until WLProgram.split_rule has been called, receive the position of
      # the last bound atom if there are unbound.
      @split_pos = nil
      # atom to use for local rule
      @bound = []
      # atom left to further processing
      @unbound = []
      
      super(a1,a2,a3)
    end

    public

    # prints to the screen information about the rule
    def show
      puts "Class name : #{self.class}"
      puts "Head : #{show_head}"
      puts "Body : #{show_body}"
      puts "--------------------------------------------------------"
    end

    # @return [WLAtom] the head atom of the rule
    def head
      unless @head
        @head = self.atom
      end
      @head
    end

    # @return [Array] array of WLAtoms in the body of this rule
    def body
      if @body.nil?
        array=[];
        self.atoms.get_atoms.each do |ato|
          if ato.is_a? WLBud::WLAtom
            array << ato
          else
            raise WLErrorGrammarParsing, "errror while parsing body atoms of #{self.show} it seems that #{ato} is not recognized as an atom"
          end
        end
        @body = array
      end
      return @body
    end    

    # The logical peer name ie. disambiguated according to the local program
    # knowledge.
    #
    # @return [Array] the list of name of peers appearing in atoms, it could be
    # different from self.peer_name.text_value when called by {WLProgram} since
    # disambiguation could have modified this field.
    def peername
      arr = [head.peername]
      atoms.get_atoms.each { |atom| arr << atom.peername }
      arr
    end

    def map_peername! &block
      head.peername = yield head.peername
      atoms.get_atoms.each { |atom| atom.peername = yield atom.peername } if block_given?
    end

    # Make dictionary : creates hash dictionaries for WLvariables and constants.
    # These dictionaries takes as key the field value as it appears in the .wl
    # file along with their position in the rule to disambiguate in case of self
    # joins.  As value it's location in the following format :
    # 'relation_pos.field_pos'
    #
    # Detect variable by checking field names starting with a '$' sign.  This
    # populate the two dictionaries dic_wlconst and dic_wlvar and the relation
    # dictionary with its reverse.
    def make_dictionaries
      unless @dic_made
        self.body.each_with_index do |atom,n|
          # field variable goes to dic_wlvar and constant to dic_wlconst
          atom.fields.each_with_index do |f,i|
            str = "#{n}.#{i}"
            if f.variable?
              var = f.token_text_value
              if self.dic_wlvar.has_key?(var)
                self.dic_wlvar[var] << str
              else
                self.dic_wlvar[var]=[str]
              end
            else
              const = f.token_text_value
              if self.dic_wlconst.has_key?(const)
                self.dic_wlconst[const] << str
              else
                self.dic_wlconst[const]=[str]
              end
            end
          end
          # PENDING list only the useful relation, a relation is useless if it's
          # arity is more than zero and none variable and constant inside are
          # used in other relation of this rule. Insert here the function
          if self.dic_relation_name.has_key?(atom.fullrelname)
            self.dic_relation_name[atom.fullrelname] << n
          else
            self.dic_relation_name[atom.fullrelname]=[n]
          end
          self.dic_invert_relation_name[n] = atom.fullrelname
        end        
      end
      @dic_made = true
    end

    # Set a unique id for this rule for the peer which has parsed this rule
    def rule_id= int
      @rule_id = int
      @rule_id.freeze
    end

    # Get the unique id for this rule
    def rule_id
      if @rule_id.nil?
        raise WLError, <<-"EOS"
this rule has been parsed but no valid id has been assigned for unknown reasons
        EOS
      else
        return @rule_id
      end
    end

    def author= name
      @author = name
    end

    # Get the name of the peer who created this rule
    def author
      return @author
    end

    # show the instruction as stored in the wl_program
    def show_wdl_format
      str = "rule #{head.show_wdl_format} :- "
      body.each { |atom| str << "#{atom.show_wdl_format}, " }
      str.slice!(-2..-1)
      str << ";"
    end

    # Create a new rule with a new relation in the head that receive the
    # valuations of all the useful variables in the bound part of a wlrule
    #
    # Useful variable are the one appearing in the local part AND (in the
    # unbound part OR in the head)
    def create_intermediary_relation_from_bound_atoms interm_relname, interm_peername
      # select atom in the local part
      localbody = ""
      local_vars = []
      @bound.each do |atom|
        local_vars += atom.variables.flatten
        localbody << "#{atom},"
      end
      local_vars = local_vars.flatten.compact.uniq
      localbody.slice!(-1)
      # #select atom in the remote part and in the head
      remote_vars = []
      @unbound.each do |atom|
        remote_vars += atom.variables.flatten
      end
      remote_vars += head.variables.flatten
      # select the intersection of local_vars and remote_vars
      useful_vars = []
      local_vars.each do |var|
        if remote_vars.include? var
          useful_vars << var
        end
      end

      # FIXME if there is no useful variable the rule is syntactically correct
      # but logically there is useless atoms. The problem is that it will
      # generate a rewriting with a zero arity relation. I changed it here to
      # add a boolean set to true.
      if useful_vars.empty?
        dec_fields='const_bool*'
        var_fields='true'
      else
        # build the list of attributes for relation declaration (dec_fields)
        # removing the '$' of variable and create attributes names
        dec_fields=''
        var_fields=''
        useful_vars.each_index do |ind|
          useful_var = useful_vars[ind]
          dec_fields << useful_var.gsub( /(^\$)(.*)/ , interm_relname+"_\\2_"+ind.to_s+"\*," )
          var_fields << useful_var << ","
        end ; dec_fields.slice!(-1); var_fields.slice!(-1);
      end
      # new collection declaration
      interm_rel_declaration = "#{interm_relname}@#{interm_peername}(#{dec_fields})"
      # new rule to install
      interm_rel_in_rule = "#{interm_relname}@#{interm_peername}(#{var_fields})"
      new_rule = "rule #{interm_rel_in_rule}:-#{localbody};"

      return interm_rel_declaration, new_rule, interm_rel_in_rule
    end # def create_intermediary_relation_from_bound_atoms

    def build_seed_template seedatom
      raise "cannot build seed template from non seed rule" unless @seed
      raise "building a seed template from seed without unbound atoms does not make sense" if unbound.nil? or unbound.empty?
      
      template = "#{head.show_wdl_format}:-#{seedatom},"
      unbound.each do |ato|
        template << "#{ato},"
      end ; template.slice!(-1);
      template = "rule #{template};"
      return template
    end # build_seed_template

    private

    def show_head
      self.head.show
    end

    def show_body
      s=""
      self.atoms.elements.each do |rf|
        if rf.is_a?(WLBud::WLAtom)
          s << rf.show
        else
          if rf.elements.first.is_a?(WLBud::WLAtom)
            s << rf.elements.first.show
          else
            raise WLErrorGrammarParsing
          end
        end
        return s
      end
    end
  end

  # The WLrule class is used to store the content of parsed WL facts.
  class WLFact < WLVocabulary
    include WLBud::NamedSentence

    attr_accessor :peername

    def initialize (a1,a2,a3)
      @contents=nil
      super(a1,a2,a3)
    end
    # prints to the screen information about the extensional fact.
    def show
      str = "Class name : #{self.class}"
      str << "Content : #{self.text_value}"
      str <<  "Relation name : #{self.fullrelname}"
      str <<  "Peer name: #{self.peer_name.text_value}"
      str <<  "Data content : #{self.content}"
      return str
    end

    # @return [Array] list of strings containing each attribute value of the
    # fact. maybe be changed if disamb_fields has been called
    def content
      if @contents.nil?
        array = []
        self.items.get_items.each {|s| array << s.item_text_value}
        @contents = array
      end
      return @contents
    end

    def map_content! &block
      self.items.get_items.each { |item| item.item_text_value = yield item.item_text_value } if block_given?
    end

    # Return the name of the peer, it could be different from
    # self.peer_name.text_value when called by {WLProgram} since disambiguation
    # could have modified this field
    def peername
      unless @peername
        @peername = self.peer_name.text_value
      end
      return @peername
    end

    def relname
      unless @relname
        @relname = self.relation_name.text_value
      end
      return @relname
    end

    def map_peername! &block
      @peername = yield peername if block_given?
    end

    # returns the name of the relation of the fact.
    def fullrelname
      return "#{self.relname}_at_#{self.peername}"
    end

    def show_wdl_format
      str = ""
      str << "#{self.relname}@#{self.peername}"
      str << "( "
      items.get_items.each { |i| str << "#{i.item_text_value}, " }
      str.slice!(-2..-1)
      str << " ) ;"
    end
  end

  module WLItem
    attr_accessor :item_text_value

    def item_text_value
      unless @item_text_value
        @item_text_value = ""
        self.elements.each do |e|
          if self.is_a? WLWord
            @item_text_value = self.text_value
          elsif self.is_a? WLItem and self.complex_string.is_a? WLComplexString
            @item_text_value = self.complex_string.text_value
          end
        end
      end
      return @item_text_value
    end
    def variable?
      false
    end
  end

  class WLWord < WLVocabulary
    def variable?
      false
    end
  end

  class WLComplexString < WLVocabulary
    def variable?
      false
    end
  end

  # The WLcollection class is used to store the content of parsed WL relation
  # names (Bloom collection) that is the declaration of predicate in the
  # beginning of the program file.
  class WLCollection < WLVocabulary
    include WLBud::NamedSentence

    attr_reader :type, :persistent, :peername

    def initialize(a1,a2,a3)
      @schema=nil
      @fields=nil
      @type=nil
      @persistent=false
      super(a1,a2,a3)
    end

    public
    # prints to the screen information about the extensional fact.
    def show
      puts "Class name : #{self.class}"
      puts "Content : #{self.text_value}"
      puts "Relation name : #{self.fullrelname}"
      puts "Schema key(s) : #{self.col_fields.keys.text_value}"
      puts "Schema value(s) : #{self.col_fields.values.text_value}"
      puts "--------------------------------------------------------"
    end

    # This method generates the schema corresponding to this 'collection'
    def schema
      if @schema.nil?
        keys = [];
        values=[];
        self.col_fields.keys.text_value.split(',').each do |s|
          key = s.split('*').first.strip.to_sym
          keys << key unless key.empty?
        end
        self.col_fields.values.text_value.split(',').each do |s|
          val = s.strip.to_sym
          values << val unless val.empty?
        end
        h = {keys => values}
        @schema=h
      end # if @schema.nil?
      return @schema
    end # schema

    # @return [Symbol] the relation type :Intensional :Extensional or
    # :Intermediary
    def get_type
      rel_type.type
    end

    # Return true if it is a persistent relation
    def persistent?
      return rel_type.persistent?
    end

    # Return the name of the peer, it could be different from
    # self.peer_name.text_value when called by {WLProgram} since disambiguation
    # could have modified this field
    #
    def peername
      unless @peername
        @peername = self.peer_name.text_value
      end
      return @peername
    end

    def map_peername!
      @peername = yield peername if block_given?
    end

    # Return an array of strings containing each element of the Fact.
    #
    def fields
      if @fields.nil?
        array=[];
        self.col_fields.keys.elements.each {|s| array << s.text_value.split('*').first}
        self.col_fields.values.elements.each {|s| array << s.text_value.split(',').first}
        @fields=array
      end
      return @fields
    end

    # Number of fields for this relation
    def arity
      if @arity.nil?
        if self.col_fields.empty?
          @arity = 0
        else
          @arity = self.col_fields.keys.elements.size + self.col_fields.values.elements.size
        end
      end
      return @arity
    end

    # This method gives the name of the relation.
    def relname
      self.relation_name.text_value
    end

    def fullrelname
      return "#{relname}_at_#{peername}"
    end

    def make_extended
      str = "collection #{get_type.to_s.downcase} "
      str << "persistent" + " " if self.persistent?
      str << relname
      str << "_plus@"
      str << peername
      str << "( priv*, #{col_fields.text_value}, plist ) ;"
    end

    def make_rext(id)
      str = "collection #{get_type.to_s.downcase} "
      str << "persistent" + " " if self.persistent?
      str << "rext_#{id}_#{relname}@#{self.peername}"
      str << "(priv*, #{col_fields.text_value}, plist) ;"
    end

    # Return the name of this atom in the format "relation_at_peer"
    #
    # Create a string for the name of the relation that fits bud restriction
    #
    # It substitute @ by '_at_'
    #
    def atom_name
      raise WLErrorTyping, "try to create a name for an atom: #{self.class} which is not a WLCollection object." unless self.is_a?(WLCollection)
      return "#{self.relation_name.text_value}_at_#{self.peername}"
    end

    def show_wdl_format
      str = ""
      str << get_type.to_s.downcase + " "
      str << "persistent" + " " if self.persistent?
      str << "#{relname}@#{peername}"
      str << "( #{col_fields.text_value} ) ;"
    end
  end

  # Object return by wlcollection.rel_type
  class WLRelType < WLVocabulary
    attr_reader :type
    def initialize (a1,a2,a3)
      super(a1,a2,a3)
      @type=nil
      @persistent=false
    end
    def persistent?
      return @persistent
    end
    def intensional?
      return @type == :Intensional
    end
    def extensional?
      return @type == :Extensional
    end
    def intermediary?
      return @type == :Intermediary
    end
  end

  class WLExtensional < WLRelType
    def initialize (a1,a2,a3)
      super(a1,a2,a3)
      @type = :Extensional
      @persistent = nil
    end
    def to_s
      return "extensional"
    end
    def persistent?
      if @persistent.nil?
        @persistent = (not persistent.elements.nil?)
      else
        return @persistent
      end
    end
  end

  class WLIntensional < WLRelType
    def initialize (a1,a2,a3=nil)
      # a3 default value is nil since WLIntensional rule is terminal node the
      # elements methods is not available
      super(a1,a2,a3)
      @type = :Intensional
      @persistent=false
    end
    def to_s
      return "intensional"
    end
  end

  class WLIntermediary < WLRelType
    def initialize (a1,a2,a3)
      super(a1,a2,a3)
      @type = :Intermediary
      @persistent = nil
    end
    def to_s
      return "intermediary"
    end
    def persistent?
      if @persistent.nil?
        @persistent = (not persistent.elements.nil?)
      else
        return @persistent
      end
    end
  end

  # This is the text part of fields in relation, it could be a constant or a
  # variable
  module WLRToken
    # By default WLRtoken is not a variable unless this method is override by
    # WLVar
    def variable?
      if self.kind_of?(WLVar)
        true
      else
        false
      end
    end

    # @return [String] the content as text of the token which could be a
    # variable or a constant
    def token_text_value
      if self.is_a? WLItem
        item_text_value
      else
        text_value
      end
    end
  end

  module WLVar
    # variable? is override here against previous mixins of modules
    def variable?
      true
    end
    def anonymous?
      self.terminal? and self == '$_' ? true : false
    end
  end

  # WebdamLog Atom, element of a WLRule: rrelation@rpeer(rfields)
  class WLAtom < WLVocabulary
    include WLBud::NamedSentence

    attr_accessor :peername, :rproven

    def initialize (a1,a2,a3)
      @name_choice=false
      @variables=nil
      super(a1,a2,a3)
    end

    #   Return the name of the peer, it could be different from
    #   self.peer_name.text_value when called by {WLProgram} since
    #   disambiguation could have modified this field
    #
    def peername
      unless @peername
        @peername = self.rpeer.text_value
      end
      return @peername
    end

    #   @return [String] relationname without the peer name
    def relname
      unless @relname
        @relname = self.rrelation.text_value
      end
      return @relname
    end

    def relname= name
        @relname = name
    end

    def map_peername! &block
      @peername = yield peername if block_given?
    end

    # @return [Array] the variables included in the atom in an array format
    # [relation_var,peer_var,[field_var1,field_var2,...]]
    def variables
      if @variables.nil?
        vars = []
        # Check if relation and/or peer are variables.
        if self.rrelation.variable? then vars << self.rrelation.text_value else vars << nil end
        if self.rpeer.variable? then vars << self.rpeer.text_value else vars << nil end
        vars << self.rfields.variables
        @variables=vars
      end
      return @variables
    end

    # return [Boolean] true if relation or peer name is a variable
    def variable?
      rrelation.variable? or rpeer.variable? ? true : false
    end

    # @return [Array] list of WLRToken as the fields of the atom (variables and
    # constants) in an array format
    def fields
      self.rfields.fields
    end

    def provenance
      self.rproven
    end

    # This method gives the name of the relation. It may also change the name of
    # the relation on this rule only, in order to implement renaming strategies
    # for self joins. @return [String] relationname_at_peername
    def fullrelname(newname=nil)
      if newname
        @fullrelname = newname=nil
      else
        unless @fullrelname
          @fullrelname = "#{self.relname}_at_#{self.peername}"
        end
      end
      return @fullrelname
    end

    # Pretty print for atoms
    def show
      str = "\n\t-#{self.class} , #{text_value},"
      variables
      if @variables[0].nil?
        str << self.rrelation.text_value << " "
      else
        @variables[0]
      end
      if @variables[1].nil?
        str << self.rpeer.text_value << " "
      else
        @variables[1]
      end
      str << fields.inspect << "\n"
    end

    def show_wdl_format
      if self.rproven == nil || self.rproven.empty?
        return "#{self.relname}@#{self.peername}(#{self.rfields.show_wdl_format})"
      else
        if self.rproven.type == :Hide
          return "[HIDE #{self.relname}@#{self.peername}(#{self.rfields.show_wdl_format})]"
        elsif self.rproven.type == :Preserve
          return "[PRESERVE #{self.relname}@#{self.peername}(#{self.rfields.show_wdl_format})]"
        end
      end
    end
  end

  class WLProvenance < WLVocabulary
    attr_reader :type
    def initialize (a1,a2,a3)
      super(a1,a2,a3)
      @type=nil
    end
    def hide?
      return @type == :Hide
    end
    def preserve?
      return @type == :Preserve
    end
  end

  class WLProvHide < WLProvenance
    def initialize (a1,a2,a3=nil)
      super(a1,a2,a3)
      @type = :Hide
    end
    def to_s
      return "hide"
    end
  end

  class WLProvPreserve < WLProvenance
    def initialize (a1,a2,a3=nil)
      super(a1,a2,a3)
      @type = :Preserve
    end
    def to_s
      return "preserve"
    end
  end

  module WLRRelation
    def variables?
      self.variable ? true : false
    end
  end

  module WLRPeer
    def variables?
      self.variable ? true : false
    end
  end

  # The Rfields class corresponds contains the fields of atoms in rules.
  class WLRfields < WLVocabulary
    def initialize(a1,a2,a3)
      @fields=nil
      @variables=nil
      super(a1,a2,a3)
    end

    # remove the comma and return an array of rtokens (rule tokens)
    def get_rtokens
      [first_rtoken] + list_rtokens.elements.map{ |comma_and_item| comma_and_item.other_rtoken }
    end

    # this methods gives only variable fields (in text value)
    def variables
      if @variables.nil?
        f = []
        get_rtokens.each { |t| f << t.text_value if t.variable? }
        @variables=f
      end
      return @variables
    end
    
    # @return [Array] list of WLRToken
    def fields
      if @fields.nil?
        f = []
        get_rtokens.each { |t| f << t }
        @fields=f
      end
      return @fields
    end

    def show_wdl_format
      str = ""
      fields.each { |f| str << "#{f.text_value}, " }
      str.slice!(-2..-1)
      str
    end
  end

  class WLPeerDec < WLVocabulary
    include WLBud::NamedSentence

    attr_accessor :peername

    # Return the name of the peer, it could be different from
    # self.peer_name.text_value when called by {WLProgram} since disambiguation
    # could have modified this field
    #
    def peername
      unless @peername
        @peername = self.peer_name.text_value
      end
      return @peername
    end

    def map_peername! &block
      @peername = yield peername if block_given?
    end

    def address
      self.peer_address.text_value
    end

    def ip
      self.peer_address.ip.text_value
    end

    def port
      self.peer_address.port.text_value
    end

    def show_wdl_format
      return "#{peername} #{ip} : #{port};"
    end
  end

  module WLComment
    def show
      puts "--------------------------------------------------------"
      puts "comment: #{text_value}"
    end

    def comment?
      true
    end
  end

  class WLPolicy < WLVocabulary

    attr_reader :ractype

    def initialize (a1,a2,a3)
      super(a1,a2,a3)
    end

    public
    def show
      puts "Class name : #{self.class}"
      puts "Relation name : #{self.relname}"
      puts "Peers : #{self.access.text_value}"
      puts "Privilege : #{self.ractype.text_value}"
    end

    def show_wdl_format
      str = "policy "
      str << self.relname
      str << " "
      if self.access_type.read?
        str << "read "
      elsif self.access_type.write?
        str << "write "
      elsif self.access_type.grant?
        str << "grant "
      end
      if self.access.all?
        str << "ALL"
      else
        str << self.access.value
      end
    end

    def relname
      unless @relname
        @relname = self.relation_name.text_value
      end
      return @relname
    end

    def access_type
      self.ractype
    end
  end      

  class WLAccessType < WLVocabulary
    attr_reader :type
    def initialize (a1,a2,a3)
      super(a1,a2,a3)
      @type=nil
    end
    def read?
      return @type == :Read
    end
    def write?
      return @type == :Write
    end
    def grant?
      return @type == :Grant
    end
  end

  class WLRead < WLAccessType
    def initialize (a1,a2,a3=nil)
      super(a1,a2,a3)
      @type = :Read
    end
    def to_s
      return "R"
    end
  end

  class WLWrite < WLAccessType
    def initialize (a1,a2,a3=nil)
      super(a1,a2,a3)
      @type = :Write
    end
    def to_s
      return "W"
    end
  end

  class WLGrant < WLAccessType
    def initialize (a1,a2,a3=nil)
      super(a1,a2,a3)
      @type = :Grant
    end
    def to_s
      return "G"
    end
  end

  module WLAccess
    def all?
      self.text_value == 'ALL'
    end

    def relation?
      self.text_value.include?('_at_') or self.text_value.include?('@')
    end

    def relname
      unless @relname
        @relname = self.relation_name.text_value
      end
      return @relname
    end

    def peername
      unless @peername
        @peername = self.peer_name.text_value
      end
      return @peername
    end

    def fullrelname
      return "#{self.relname}_at_#{self.peername}"
    end


    def value
      self.text_value
    end
  end
end
