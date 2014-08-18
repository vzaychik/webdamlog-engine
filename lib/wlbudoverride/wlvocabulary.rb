module WLBud

  # The WLrule class is used to store the content of parsed WLRules
  class WLRule < WLVocabulary
    include WLBud::NamedSentence

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

    def author= name
      @author = name
    end

    # Get the name of the peer who created this rule
    def author
      return @author
    end
  end

  # The WLcollection class is used to store the content of parsed WL relation
  # names (Bloom collection) that is the declaration of predicate in the
  # beginning of the program file.
  class WLCollection < WLVocabulary
    include WLBud::NamedSentence

    public

    def make_extended
      str = "collection #{get_type.to_s.downcase} "
      str << "persistent" + " " if self.persistent?
      str << relname
      str << "_plus@"
      str << peername
      str << "( priv*, #{col_fields.text_value}, plist ) ;"
    end

    def is_extended?
      if relname.contains? "_plus@" or relname.contains? "_plus_at_"
        return true
      else
        return false
      end
    end

    def make_rext(id)
      str = "collection #{get_type.to_s.downcase} "
      str << "persistent" + " " if self.persistent?
      str << "rext_#{id}_#{relname}@#{self.peername}"
      str << "(priv*, #{col_fields.text_value}, plist) ;"
    end
  end

  # WebdamLog Atom, element of a WLRule: rrelation@rpeer(rfields)
  class WLAtom < WLVocabulary
    include WLBud::NamedSentence

    attr_accessor :rproven

    def relname= name
        @relname = name
    end

    def provenance
      self.rproven
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

end #module WLBud
