require_relative 'webdamlog_runner.rb'
require_relative 'wlbudaccess.rb'

module WLARunner 
  include WLRunner
  include WLBudAccess

  public 

  # Create a new webdamlog engine object ready to be run
  # have to override this method because of wacky hacky class messing
  def self.create (username, pg_file, port, options={})
    klass = WLAEnginePool.create username, port
    options[:port] = port
    # FIXME Hacky way to get the rules and collections from bootstrap program
    # for WePiM
    klass.module_eval { attr_accessor :bootstrap_program}
    klass.module_eval { attr_accessor :bootstrap_collections}
    klass.module_eval { attr_accessor :bootstrap_rules}
    klass.module_eval { attr_accessor :bootstrap_policies}
    obj = klass.new(username, pg_file, options)
    # Loading twice the file from io. could find another way but need clear
    # interface from wl_bud
    obj.bootstrap_program = pg_file ? open(pg_file).readlines.join("").split(";").map {|stmt| "#{stmt};"} : []
    obj.bootstrap_collections = obj.bootstrap_program ? obj.bootstrap_program.select {|stmt| stmt.lstrip()[0..9]=='collection' } : []
    obj.bootstrap_rules = obj.bootstrap_program ? obj.bootstrap_program.select {|stmt| stmt.lstrip()[0..3]=='rule' } : []
    obj.bootstrap_policies = obj.bootstrap_program ? obj.bootstrap_program.select {|stmt| stmt.lstrip()[0..3]=='policy' } : []
    obj.extend WLARunner
    return obj
  end

  # Stop and delete the webdamlog engine
  def delete
    self.stop
    WLAEnginePool.delete self.class
  end
  
  def update_acl (rel, peer, priv)
    sync_do do
      begin
        self.tables["acle_at_#{self.peername}".to_sym] <+ [["#{peer}","#{priv}","#{rel}"]]
      rescue WLError => e
        puts e
      end
    end
  end
  
  
  # The method remove_acl removes the priviledges from a running peer
  # In WebdamLog <- operator is used to delete a fact
  # The method takes three arguments relation, peername and priviledge and removes the set from the table
  def delete_acl (rel, peer, priv)
    sync_do do
      begin
        self.tables["acle_at_#{self.peername}".to_sym] <- [["#{peer}","#{priv}","#{rel}"]]
        # WLError raises error if something goes wrong
      rescue WLError => e
        puts e
      end
    end
  end
  
  # @return [Array] list of policies declared in wdl
  def snapshot_policies
    coll = []
    sync_do do
      coll = self.wl_program.wlpolicies
    end
    return coll.map{ |p| p.show_wdl_format}
  end
  
  private

  class WLAEnginePool
    class << self

      attr_reader :engines

      # Create the new class to instantiate to be a webdamlog engine
      def create username, port
        @engines ||= {}
        ano_klass = Class.new WLBudAccess::WLA
        klass_name = create_new_class_name(username, port)
        klass = Object.const_set(klass_name, ano_klass)
        @engines[klass.object_id] = [klass_name, klass]
        return klass
      end
      
      # Remove WLRunner from the pool
      def delete obj
        raise(WLBud::WLErrorRunner, "try to delete from the pool the class of an engine which is not a Class object type") unless obj.is_a? Class
        klass_name, klass = @engines[obj.object_id]
        @engines.delete(obj.object_id)
        Object.send(:remove_const, klass_name) unless klass_name.nil? or !Object.const_defined?(klass_name)
      end

      def create_new_class_name username, port
        return "ClassWLEngineOf#{username}On#{port}".split('_').collect!{ |w| w.capitalize }.join.to_sym
      end
    end
  end # end class WLAEnginePool

end
