require_relative '../../lib/access_runner'
require_relative '../../lib/wlbud/wlerror'
require 'csv'

XP_FILE_DIR = ARGV.first if defined?(ARGV)
XPFILE = "XP_NOACCESS"
WRITEABLEFILE = "writeable.wdm"
DELETESFILE = "deletes.wdm"

# Parameters:
# * XP_FILE_DIR : The path to the directory with the data generator
#
# By convention :
# * there should be a CSV file named XP_NOACCESS with the list of peer name to
#   start.
# * the program file name of each peer must be an underscore separated string.
#   The last field must be the peername.
def run_access_remote!
  if ARGV.include?("access")
    @access_mode = true
    p "starting experiment with access control on"
  end
  if ARGV.include?("optim1")
    @optim1 = true
    @access_mode = true
    p "optimization 1 is on"
    #load writeable
    writeable = {}
    File.readlines("#{XP_FILE_DIR}/#{WRITEABLEFILE}").each do |fact|
      #parse out the peer and hash by that
      fact[/.*@([a-zA-Z0-9]+)\(/]
      name = $1
      writeable[name] = [] if writeable[name].nil? 
      writeable[name] << fact
    end
  end
  if ARGV.include?("optim2")
    @optim2 = true
    @access_mode = true
    p "optimization 2 - formulas - is on"
  end
  if ARGV.include?("deletes")
    @wdeletes = true
    @deletes = {}
    #FIXME rewrite using regular webdamlog parsing
    File.readlines("#{XP_FILE_DIR}/#{DELETESFILE}").each do |fact|
      #parse out the peer and hash by that
      fact[/fact (.*)@([a-zA-Z0-9]+)\(/]
      relname = "#{$1}_at_#{$2}"
      pname = $2
      fact[/\((.*)\)/]
      #fix the quotes
      tuple = $1.gsub(/\"/,'').split(',')
      @deletes[pname] = {} if @deletes[pname].nil?
      @deletes[pname][relname] = [] if @deletes[pname][relname].nil?
      @deletes[pname][relname] << tuple
    end
  end

  xpfiles = []
  expected_tuples = -1
  expected_afterdel = -1
  #first row is the list of peers
  CSV.foreach(get_run_xp_file) do |row|
    if (xpfiles == [])
      xpfiles = row
      p "Start experiments with #{xpfiles}"
    elsif expected_tuples < 0
      expected_tuples = row.first.to_i
    else
      expected_afterdel = row.first.to_i
    end
  end

  if expected_tuples < 1
    p "This scenario will not generate any results, so not running"
    exit 1
  end

  runners = []
  @hosts = []
  xpfiles.each do |f|
    filename = File.join(XP_FILE_DIR,f)
    runners << create_wl_runner(filename)
    p "#{runners.last.peername} created"
    if (runners.last.peername.start_with? "master" or runners.last.peername.start_with? "sue" or runners.last.peername.start_with? "alice")
      #get a list of all hosts
      file = File.new filename, "r"
      while line = file.gets
        if /^peer/.match line
          hostname = line.split("=").last.split(":").first
          if !@hosts.include?(hostname)
            puts "adding host #{hostname}"
            @hosts << hostname
          end
        end
      end
      file.close
    end
  end
  
  runners.each do |runner|
    runner.on_shutdown do
      p "Final tick step of #{runner.peername} : #{runner.budtime}"
    end
  end

  not_done = true

  runners.each do |runner|
    if @optim1
      writeable[runner.peername].each { |fct|
        runner.add_facts fct
      }
    end
    runner.run_engine
    p "#{runner.peername} started"
    if runner.peername == "master0"
      @masterp = runner
      @scenario = "network"
    elsif runner.peername.start_with?("sue")
      @masterp = runner
      @scenario = "album"
    elsif runner.peername.start_with?("alice")
      if @masterp.nil?
        @masterp = runner
        @scenario = "closure"
      end
    end
  end

  mdeletesdone = false
  
  if @masterp != nil
    if @scenario == "network"
      resultrel = "t_i"
    elsif @scenario == "album"
      resultrel = "album_i"
    elsif @scenario == "closure"
      resultrel = "all_friends_i"
    end
    if @access_mode == true
      resultrel += "_plusR_at_#{@masterp.peername}"
    else
      resultrel += "_at_#{@masterp.peername}"
    end
    
    @masterp.register_callback(resultrel.to_sym) do
      numres = @masterp.tables[resultrel.to_sym].length
      p "new num results is #{numres}"
      if numres == expected_tuples
        if @wdeletes and !mdeletesdone
          p "start the deletion phase at #{@masterp.budtime}"
          @hosts.each do |host|
            str = "ssh #{host} \"echo done > /tmp/masterfull\""
            puts "trying to execute #{str}"
            system str
          end
          mdeletesdone = true
        elsif !@wdeletes
          p "master received all tuples"
          results = @masterp.tables[resultrel.to_sym].map{ |t| Hash[t.each_pair.to_a] }
          puts "final contents of master's facts: #{results}"
          #put a masterdone notice on all hosts running peers
          @hosts.each do |host|
            str = "ssh #{host} \"echo done > /tmp/masterdone\""
            puts "trying to execute #{str}"
            system str
          end
        end
      elsif numres == expected_afterdel and @wdeletes and mdeletesdone
        p "master received all tuples and deletions"
        results = @masterp.tables[resultrel.to_sym].map{ |t| Hash[t.each_pair.to_a] }
        puts "final contents of master's facts: #{results}"
        #put a masterdone notice on all hosts running peers
        @hosts.each do |host|
          str = "ssh #{host} \"echo done > /tmp/masterdone\""
          puts "trying to execute #{str}"
          system str
        end        
      end
    end
  end
  
  deletesdone = false
  while not_done
    p "still running"
    if File.exist?('/tmp/masterdone')
      not_done = false
      puts "Master done, shutting down"
      runners.each do |runner|
        runner.stop
      end
    elsif (!deletesdone and File.exist?('/tmp/masterfull'))
      p "injecting deletes"
      #inject deletes
      runners.each do |runner|
        fcts = @deletes[runner.peername]
        if !fcts.nil?
          p "deleting #{fcts} for peer #{runner.peername}"
          runner.delete_facts(fcts)
          runner.schedule_extra_tick
        end
      end
      deletesdone = true
    end
    sleep 10
  end

end

# Giving a program file generated from data_generators start the peer given in
# the name of the file using the address found in the program file
def create_wl_runner pg_file
  ip_addr = port = ''
  pg_splitted = pg_file.split "_"
  peername = pg_splitted.last
  file = File.new pg_file, "r"
  loop = true
  while loop and line = file.gets
    if(/^peer/.match line and line.include? peername) # find line which contains peer current peer address
      pname = line.split("=").first.strip
      if (/#{peername}$/.match pname)
        peerline = line.split("=").last.strip
        peerline.slice!(-1) # remove last ;
        ip_addr, port = peerline.split ":"
        loop = false
      end
    end
  end
  file.close
  raise WLError, "impossible to find the peername given in the end of the program \
filename: #{peername} in the list of peer specified in the program" if ip_addr.nil? or port.nil?
  puts "creating peer #{peername} on #{ip_addr}:#{port}"
  return WLARunner.create(peername, pg_file, port, {:ip => ip_addr, :measure => true, :accessc => @access_mode, :optim1 => @optim1, :optim2 => @optim2, :noprovenance => true, :debug => false, :tcp => true, :reliable => true })
end # def start_peer

def get_run_xp_file
  raise "WLXP alone is not an experiment, choose one of the xp" unless defined? XPFILE
  return File.join(XP_FILE_DIR, XPFILE)
end

run_access_remote!
